# encoding: utf-8
require "java"
require "time"

java_import java.net.http.HttpClient
java_import java.net.http.HttpRequest
java_import java.net.http.HttpResponse
java_import java.net.InetAddress
java_import java.time.Duration
java_import javax.net.ssl.SSLContext
java_import javax.net.ssl.TrustManagerFactory
java_import java.security.KeyStore
java_import java.security.cert.CertificateFactory
java_import java.io.ByteArrayInputStream

module LogStash
  module Filters
    module Stanag4778Module
      class Fetcher
        attr_reader :enabled, :allowlist, :timeout_seconds, :max_bytes,
                    :allow_private, :cache_max_bytes, :cache_ttl

        def initialize(enabled: false, allowlist: [], timeout_seconds: 10, max_bytes: 10_485_760,
                       allow_private: false, cache_max_bytes: 52_428_800, cache_ttl: 300, ca_path: nil)
          @enabled = !!enabled
          @allowlist = Array(allowlist).map { |h| h.to_s.strip.downcase }.reject(&:empty?)
          @timeout_seconds = timeout_seconds.to_i
          @max_bytes = max_bytes.to_i
          @allow_private = !!allow_private
          @cache_max_bytes = cache_max_bytes.to_i
          @cache_ttl = cache_ttl.to_i

          @cache = {} # uri => { data:, content_type:, fetched_at:, size: }
          @current_cache_bytes = 0
          @cache_mutex = Mutex.new

          builder = HttpClient.newBuilder
                              .connectTimeout(Duration.ofSeconds(@timeout_seconds))
                              .followRedirects(HttpClient::Redirect::NEVER)

          ssl_ctx = build_ssl_context(ca_path)
          builder.sslContext(ssl_ctx) if ssl_ctx

          @client = builder.build
        end

        # Fetches a URI over HTTPS with SSRF defenses and manual redirect validation.
        # Returns [true, byte_array, content_type] or [false, error_message, nil]
        def fetch(uri_str, max_redirects = 3)
          return [false, "External fetching is disabled in filter configuration", nil] unless @enabled

          # Check cache
          @cache_mutex.synchronize do
            evict_expired
            if @cache.key?(uri_str)
              entry = @cache[uri_str]
              return [true, entry[:data], entry[:content_type]]
            end
          end

          current_url = uri_str
          redirects_left = max_redirects

          while true
            valid, err, uri = validate_url(current_url)
            return [false, err, nil] unless valid

            req = HttpRequest.newBuilder(uri)
                             .timeout(Duration.ofSeconds(@timeout_seconds))
                             .header("User-Agent", "Logstash-STANAG4778-Verifier/1.1")
                             .GET
                             .build

            resp = begin
                     @client.send(req, HttpResponse::BodyHandlers.ofInputStream)
                   rescue StandardError, java.lang.Exception => e
                     return [false, "HTTP request failed: #{e.message}", nil]
                   end

            status = resp.statusCode

            # Check for redirect (301, 302, 303, 307, 308)
            if [301, 302, 303, 307, 308].include?(status)
              redirect_header = resp.headers.firstValue("Location").orElse(nil)
              return [false, "Redirect status #{status} without Location header", nil] if redirect_header.nil?

              new_uri = uri.resolve(redirect_header)
              current_url = new_uri.toString
              redirects_left -= 1
              if redirects_left < 0
                return [false, "Too many redirects (max #{max_redirects})", nil]
              end
              next
            end

            unless status >= 200 && status < 300
              return [false, "HTTP GET failed with status #{status}", nil]
            end

            # Check Content-Length header first
            cl_val = resp.headers.firstValue("Content-Length").orElse(nil)
            if cl_val && cl_val.to_i > @max_bytes
              return [false, "Content-Length #{cl_val} exceeds limit of #{@max_bytes} bytes", nil]
            end

            # Stream body up to max_bytes
            body_bytes, size_err = read_stream_capped(resp.body, @max_bytes)
            return [false, size_err, nil] if size_err

            content_type = resp.headers.firstValue("Content-Type").orElse("application/octet-stream")

            # Store in cache
            @cache_mutex.synchronize do
              add_to_cache(uri_str, body_bytes, content_type)
            end

            return [true, body_bytes, content_type]
          end
        rescue StandardError, java.lang.Exception => e
          [false, "Fetch exception: #{e.message}", nil]
        end

        def host_allowed?(host)
          @allowlist.any? do |pattern|
            if pattern.start_with?("*.")
              suffix = pattern[1..-1] # .example.org
              # Must be a subdomain, not the parent domain itself
              host.end_with?(suffix) && host != pattern[2..-1]
            else
              host == pattern
            end
          end
        end

        def clear_cache
          @cache_mutex.synchronize do
            @cache.clear
            @current_cache_bytes = 0
          end
        end

        private

        def validate_url(url_str)
          uri = begin
                  java.net.URI.create(url_str)
                rescue StandardError => e
                  return [false, "Invalid URI '#{url_str}': #{e.message}", nil]
                end

          scheme = uri.getScheme&.downcase
          unless scheme == "https"
            return [false, "Only HTTPS scheme is permitted for external references (got '#{scheme}')", nil]
          end

          host = uri.getHost&.downcase
          if host.nil? || host.empty?
            return [false, "URI has no host component", nil]
          end

          unless host_allowed?(host)
            return [false, "Host '#{host}' is not in external_reference_allowlist", nil]
          end

          unless @allow_private
            ip_valid, ip_err = check_not_private_ip(host)
            return [false, ip_err, nil] unless ip_valid
          end

          [true, nil, uri]
        end

        # Resolve DNS and verify none of the addresses are private / link-local / loopback
        def check_not_private_ip(host)
          addresses = begin
                        InetAddress.getAllByName(host)
                      rescue StandardError, java.lang.Exception => e
                        return [false, "DNS resolution failed for '#{host}': #{e.message}"]
                      end

          addresses.each do |addr|
            if addr.isAnyLocalAddress
              return [false, "Host '#{host}' resolves to any-local address #{addr.getHostAddress}"]
            end
            if addr.isLoopbackAddress
              return [false, "Host '#{host}' resolves to loopback address #{addr.getHostAddress}"]
            end
            if addr.isLinkLocalAddress
              return [false, "Host '#{host}' resolves to link-local address #{addr.getHostAddress}"]
            end
            if addr.isSiteLocalAddress
              return [false, "Host '#{host}' resolves to private/site-local address #{addr.getHostAddress}"]
            end
            if addr.isMulticastAddress
              return [false, "Host '#{host}' resolves to multicast address #{addr.getHostAddress}"]
            end

            # Check CGNAT (100.64.0.0/10) and IPv6 Unique Local (fc00::/7)
            raw = addr.getAddress
            if raw.length == 4
              b0 = raw[0] & 0xff
              b1 = raw[1] & 0xff
              if b0 == 100 && (b1 >= 64 && b1 <= 127)
                return [false, "Host '#{host}' resolves to Carrier-Grade NAT address #{addr.getHostAddress}"]
              end
            elsif raw.length == 16
              b0 = raw[0] & 0xff
              if (b0 & 0xfe) == 0xfc # fc00::/7
                return [false, "Host '#{host}' resolves to IPv6 unique local address #{addr.getHostAddress}"]
              end
            end
          end

          [true, nil]
        end

        def read_stream_capped(input_stream, max_bytes)
          buffer = Java::byte[8192].new
          baos = java.io.ByteArrayOutputStream.new
          total_read = 0

          while (n = input_stream.read(buffer, 0, buffer.length)) != -1
            total_read += n
            if total_read > max_bytes
              input_stream.close rescue nil
              return [nil, "Payload size exceeds limit of #{max_bytes} bytes"]
            end
            baos.write(buffer, 0, n)
          end

          input_stream.close rescue nil
          [baos.toByteArray, nil]
        end

        def add_to_cache(uri_str, data, cty)
          entry_size = data.length
          return if entry_size > @cache_max_bytes

          # LRU eviction if over capacity
          while (@current_cache_bytes + entry_size) > @cache_max_bytes && !@cache.empty?
            oldest_key = @cache.keys.first
            removed = @cache.delete(oldest_key)
            @current_cache_bytes -= removed[:size] if removed
          end

          @cache[uri_str] = {
            data: data,
            content_type: cty,
            fetched_at: Time.now.to_i,
            size: entry_size
          }
          @current_cache_bytes += entry_size
        end

        def evict_expired
          now = Time.now.to_i
          @cache.delete_if do |k, entry|
            if now - entry[:fetched_at] > @cache_ttl
              @current_cache_bytes -= entry[:size]
              true
            else
              false
            end
          end
        end

        def build_ssl_context(ca_path)
          return nil unless ca_path && ::File.exist?(ca_path)

          cf = CertificateFactory.getInstance("X.509")
          ks = KeyStore.getInstance(KeyStore.getDefaultType)
          ks.load(nil, nil)

          pattern = /-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/m
          idx = 0
          ::File.read(ca_path).scan(pattern) do |match|
            clean_b64 = match.first.gsub(/\s+/, "")
            bytes = Base64.decode64(clean_b64)
            cert = cf.generateCertificate(ByteArrayInputStream.new(bytes.to_java_bytes))
            ks.setCertificateEntry("ca_#{idx}", cert)
            idx += 1
          end

          tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
          tmf.init(ks)

          ctx = SSLContext.getInstance("TLS")
          ctx.init(nil, tmf.getTrustManagers, nil)
          ctx
        rescue StandardError, java.lang.Exception => e
          nil
        end
      end
    end
  end
end

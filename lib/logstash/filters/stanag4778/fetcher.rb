# encoding: utf-8
require "java"

java_import java.net.http.HttpClient
java_import java.net.http.HttpRequest
java_import java.net.http.HttpResponse
java_import java.time.Duration

module LogStash
  module Filters
    module Stanag4778Module
      class Fetcher
        attr_reader :enabled, :allowlist, :timeout_seconds, :max_bytes

        def initialize(enabled: false, allowlist: [], timeout_seconds: 10, max_bytes: 10_485_760)
          @enabled = !!enabled
          @allowlist = Array(allowlist).map { |h| h.to_s.strip.downcase }.reject(&:empty?)
          @timeout_seconds = timeout_seconds.to_i
          @max_bytes = max_bytes.to_i
          @cache = {}
          @cache_mutex = Mutex.new

          @client = HttpClient.newBuilder
                              .connectTimeout(Duration.ofSeconds(@timeout_seconds))
                              .followRedirects(HttpClient::Redirect::NORMAL)
                              .build
        end

        # Fetches a URI over HTTPS if allowed.
        # Returns [true, byte_array, content_type] or [false, error_message, nil]
        def fetch(uri_str)
          return [false, "External fetching is disabled in filter configuration", nil] unless @enabled

          uri = begin
                  java.net.URI.create(uri_str)
                rescue StandardError => e
                  return [false, "Invalid URI: #{e.message}", nil]
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

          @cache_mutex.synchronize do
            if @cache.key?(uri_str)
              return [true, @cache[uri_str][:data], @cache[uri_str][:content_type]]
            end
          end

          begin
            req = HttpRequest.newBuilder(uri)
                             .timeout(Duration.ofSeconds(@timeout_seconds))
                             .header("User-Agent", "Logstash-STANAG4778-Verifier/1.0")
                             .GET
                             .build

            resp = @client.send(req, HttpResponse::BodyHandlers.ofByteArray)
            status = resp.statusCode

            unless status >= 200 && status < 300
              return [false, "HTTP GET failed with status #{status}", nil]
            end

            body_bytes = resp.body
            if body_bytes.length > @max_bytes
              return [false, "Payload size (#{body_bytes.length} bytes) exceeds limit of #{@max_bytes} bytes", nil]
            end

            content_type = resp.headers.firstValue("Content-Type").orElse("application/octet-stream")

            @cache_mutex.synchronize do
              # Simple LRU-style eviction if cache exceeds 100 entries
              @cache.shift if @cache.size >= 100
              @cache[uri_str] = { data: body_bytes, content_type: content_type }
            end

            [true, body_bytes, content_type]
          rescue StandardError => e
            [false, "Fetch error: #{e.message}", nil]
          end
        end

        def host_allowed?(host)
          @allowlist.any? do |pattern|
            if pattern.start_with?("*.")
              suffix = pattern[1..-1] # .example.org
              host.end_with?(suffix)
            else
              host == pattern
            end
          end
        end

        def clear_cache
          @cache_mutex.synchronize { @cache.clear }
        end
      end
    end
  end
end

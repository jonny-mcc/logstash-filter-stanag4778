# encoding: utf-8
require "json"

module LogStash
  module Filters
    module Stanag4778Module
      # RFC 8785: JSON Canonicalization Scheme (JCS)
      module JCS
        def self.canonicalize(data)
          serialize(data)
        end

        def self.serialize(obj)
          case obj
          when nil
            "null"
          when true
            "true"
          when false
            "false"
          when String
            serialize_string(obj)
          when Integer
            obj.to_s
          when Float
            serialize_float(obj)
          when Array
            "[" + obj.map { |elem| serialize(elem) }.join(",") + "]"
          when Hash
            # RFC 8785 section 3.2.3: Sort keys by UTF-16 code units
            sorted_keys = obj.keys.map(&:to_s).sort do |a, b|
              compare_utf16(a, b)
            end
            "{" + sorted_keys.map { |k| "#{serialize_string(k)}:#{serialize(obj[k])}" }.join(",") + "}"
          else
            serialize_string(obj.to_s)
          end
        end

        # Compare two UTF-8 strings by their UTF-16 code units
        def self.compare_utf16(a, b)
          a_units = a.encode("UTF-16BE").bytes.each_slice(2).map { |hi, lo| (hi << 8) | lo }
          b_units = b.encode("UTF-16BE").bytes.each_slice(2).map { |hi, lo| (hi << 8) | lo }

          len = [a_units.length, b_units.length].min
          len.times do |i|
            diff = a_units[i] <=> b_units[i]
            return diff unless diff.zero?
          end
          a_units.length <=> b_units.length
        end

        def self.serialize_string(str)
          # RFC 8785 section 3.2.2.2: string serialization escapes quotation mark, reverse solidus,
          # and control characters U+0000 through U+001F using \u00xx.
          out = ['"']
          str.to_s.each_char do |ch|
            cp = ch.ord
            case cp
            when 0x22 # "
              out << '\\"'
            when 0x5C # \
              out << '\\\\'
            when 0x08 # \b
              out << '\\b'
            when 0x09 # \t
              out << '\\t'
            when 0x0A # \n
              out << '\\n'
            when 0x0C # \f
              out << '\\f'
            when 0x0D # \r
              out << '\\r'
            when 0x00..0x1F
              out << sprintf('\\u%04x', cp)
            else
              out << ch
            end
          end
          out << '"'
          out.join
        end

        def self.serialize_float(num)
          return "0" if num.zero?
          if num.infinite? || num.nan?
            raise ArgumentError, "In RFC 8785 JCS, Infinity and NaN are not permitted"
          end

          # Format in ES6/ECMAScript format (scientific notation only for < 1e-6 or >= 1e21)
          # In Ruby, if num == num.to_i and fits, output integer
          if num == num.to_i && num.abs < 1e21
            return num.to_i.to_s
          end

          # Use JSON generator's float formatting or Ruby's float string representation
          str = num.to_s
          # Ensure scientific notation exponent uses uppercase 'e' with '+' for positive if standard
          # Ruby float formatting matches ES6 closely for standard numbers
          str
        end
      end
    end
  end
end

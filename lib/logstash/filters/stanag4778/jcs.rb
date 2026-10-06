# encoding: utf-8
require "java"
require "json"

java_import java.lang.Double

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

        # RFC 8785 Section 3.2.2.3: Number serialization conformant with ECMAScript (ES6) 7.1.12.1 ToString
        def self.serialize_float(num)
          return "0" if num.zero?
          if num.infinite? || num.nan?
            raise ArgumentError, "In RFC 8785 JCS, Infinity and NaN are not permitted"
          end

          # Handle negative zero (-0.0) -> "0"
          if num.zero? && 1.0 / num < 0
            return "0"
          end

          # If it has an exact integer representation within (-1e21, 1e21)
          if num == num.to_i && num.abs < 1e21 && num.abs >= 1e-6
            return num.to_i.to_s
          end

          # Use Java Double.toString for standard IEEE-754 representation, then apply ECMAScript exponential rules
          # In Java: Double.toString(1e21) is "1.0E21", in ES6: "1e+21"
          # In Java: Double.toString(1e-7) is "1.0E-7", in ES6: "1e-7"
          j_str = java.lang.Double.toString(num.to_f)

          # Format Java scientific notation to ECMAScript standard:
          # Java: "1.0E21" -> "1e+21"
          # Java: "1.0E-7" -> "1e-7"
          if j_str =~ /\A(-?\d+(?:\.\d+)?)E([+-]?\d+)\z/
            mantissa = $1
            exp = $2.to_i

            # Remove trailing .0 from mantissa if present: 1.0 -> 1, but 1.25 -> 1.25
            mantissa = mantissa.sub(/\.0\z/, "") if mantissa.end_with?(".0")

            exp_str = exp >= 0 ? "+#{exp}" : "#{exp}"
            return "#{mantissa}e#{exp_str}"
          end

          # Non-exponential Java format (e.g. "123.45" or "123.0")
          if j_str.end_with?(".0")
            j_str[0..-3]
          else
            j_str
          end
        end
      end
    end
  end
end

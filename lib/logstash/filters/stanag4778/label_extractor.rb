# encoding: utf-8
require "logstash/filters/stanag4778/profile"

module LogStash
  module Filters
    module Stanag4778Module
      # Extracts STANAG 4774 Confidentiality Metadata Labels from XML and JSON bindings
      module LabelExtractor
        def self.extract(bindings)
          labels = []
          return labels unless bindings.is_a?(Array)

          bindings.each do |b|
            meta = b[:metadata]
            next unless meta

          # Case 1: JSON metadata object (hash with @context, ocl, etc.)
          if meta.is_a?(Hash)
            extract_json_labels(meta, labels)
          # Case 2: XML metadata representation (array of dom_to_hash elements)
          elsif meta.is_a?(Array)
            meta.each { |item| extract_xml_label(item, labels) }
          end
        end

        stringify_keys(labels)
      end

      def self.stringify_keys(obj)
        case obj
        when Hash
          obj.each_with_object({}) { |(k, v), h| h[k.to_s] = stringify_keys(v) }
        when Array
          obj.map { |item| stringify_keys(item) }
        else
          obj
        end
      end

        def self.extract_json_labels(meta_hash, labels)
          # Look for "ocl" (originator confidentiality label) or "acl" (alternative confidentiality label)
          ["ocl", "acl"].each do |key|
            if meta_hash.key?(key) && meta_hash[key].is_a?(Hash)
              lbl = meta_hash[key]
              labels << {
                type: key == "ocl" ? "originator" : "alternative",
                policy_identifier: lbl["pol"],
                classification: lbl["cls"],
                creation_datetime: lbl["dcr"],
                review_datetime: lbl["drv"],
                categories: parse_json_categories(lbl["catl"])
              }
            end
          end
        end

        def self.parse_json_categories(catl)
          return [] unless catl.is_a?(Array)
          catl.map do |c|
            next unless c.is_a?(Hash)
            {
              type: c["type"],
              name: c["name"],
              values: c["vals"]
            }
          end.compact
        end

        def self.extract_xml_label(node, labels)
          return unless node.is_a?(Hash)

          tag = node[:tag].to_s
          ns  = node[:namespace].to_s

          is_slab = (ns == Profile::NS_SLAB_4774 || ns == Profile::NS_SLAB_4774_ALT)

          if is_slab || tag.include?("ConfidentialityLabel")
            label_type = tag.start_with?("originator") ? "originator" : "alternative"
            parsed = { type: label_type }

            children = node[:children] || []
            children.each do |child|
              c_tag = child[:tag].to_s
              if c_tag == "ConfidentialityInformation"
                (child[:children] || []).each do |info_child|
                  case info_child[:tag].to_s
                  when "PolicyIdentifier"
                    parsed[:policy_identifier] = info_child[:value]
                  when "Classification"
                    parsed[:classification] = info_child[:value]
                  when "Category"
                    parsed[:categories] ||= []
                    cat_vals = (info_child[:children] || []).map { |cv| cv[:value] }
                    parsed[:categories] << { values: cat_vals }
                  end
                end
              elsif c_tag == "CreationDateTime"
                parsed[:creation_datetime] = child[:value]
              elsif c_tag == "ReviewDateTime"
                parsed[:review_datetime] = child[:value]
              end
            end

            labels << parsed if parsed[:policy_identifier] || parsed[:classification]
          elsif node[:children]
            node[:children].each { |child| extract_xml_label(child, labels) }
          end
        end
      end
    end
  end
end

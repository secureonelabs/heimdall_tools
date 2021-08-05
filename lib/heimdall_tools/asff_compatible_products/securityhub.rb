require 'csv'
require 'json'

module HeimdallTools
  class SecurityHub
    private_class_method def self.corresponding_control(controls, finding)
      controls.find { |c| c['StandardsControlArn'] == finding['ProductFields']['StandardsControlArn'] }
    end

    def self.supporting_docs(standards:)
      begin
        controls = standards.nil? ? nil : standards.map { |s| JSON.parse(s)['Controls'] }.flatten
      rescue StandardError => e
        raise "Invalid supporting docs for Security Hub:\nException: #{e}"
      end

      begin
        resource_dir = Pathname.new(__FILE__).join('../../../data')
        aws_config_mapping_file = File.join(resource_dir, 'aws-config-mapping.csv')
        aws_config_mapping = CSV.read(aws_config_mapping_file, { encoding: 'UTF-8', headers: true, header_converters: :symbol }).map(&:to_hash)
      rescue StandardError => e
        raise "Invalid AWS Config mapping file:\nException: #{e}"
      end

      { controls: controls, aws_config_mapping: aws_config_mapping }
    end

    def self.finding_id(finding, *, encode:, controls: nil, **)
      ret = if !controls.nil? && !(control = corresponding_control(controls, finding)).nil?
              control['ControlId']
            elsif finding['ProductFields'].member?('ControlId') # check if aws
              finding['ProductFields']['ControlId']
            elsif finding['ProductFields'].member?('RuleId') # check if cis
              finding['ProductFields']['RuleId']
            else
              finding['GeneratorId'].split('/')[-1]
            end
      encode.call(ret)
    end

    def self.finding_impact(finding, *, controls: nil, **)
      if !controls.nil? && !(control = corresponding_control(controls, finding)).nil?
        imp = control['SeverityRating'].to_sym
      else
        # severity is required, but can be either 'label' or 'normalized' internally with 'label' being preferred.  other values can be in here too such as the original severity rating.
        imp = finding['Severity'].key?('Label') ? finding['Severity']['Label'].to_sym : finding['Severity']['Normalized']/100.0
        # securityhub asff file does not contain accurate severity information by setting things that shouldn't be informational to informational: when additional context, i.e. standards, is not provided, set informational to medium.
        imp = :MEDIUM if imp.is_a?(Symbol) && imp == :INFORMATIONAL
      end
      imp
    end

    def self.finding_nist_tag(finding, *, aws_config_mapping:, **)
      return {} unless finding['ProductFields']['RelatedAWSResources:0/type'] == 'AWS::Config::ConfigRule'

      aws_config_mapping.select { |rule| finding['ProductFields']['RelatedAWSResources:0/name'].include? rule[:awsconfigrulename] }
    end

    def self.finding_title(finding, *, encode:, controls: nil, **)
      ret = if !controls.nil? && !(control = corresponding_control(controls, finding)).nil?
              control['Title']
            else
              finding['Title']
            end
      encode.call(ret)
    end

    def self.product_name(findings, *, encode:, **)
      # "#{findings[0]['ProductFields']['aws/securityhub/CompanyName']} #{findings[0]['ProductFields']['aws/securityhub/ProductName']}"
      # not using above due to wanting to provide the standard's name instead
      if findings[0]['Types'][0].split('/')[-1].gsub(/-/, ' ').downcase == findings[0]['ProductFields']['StandardsControlArn'].split('/')[-4].gsub(/-/, ' ').downcase
        standardname = findings[0]['Types'][0].split('/')[-1].gsub(/-/, ' ')
      else
        standardname = findings[0]['ProductFields']['StandardsControlArn'].split('/')[-4].gsub(/-/, ' ').split.map(&:capitalize).join(' ')
      end
      encode.call("#{standardname} v#{findings[0]['ProductFields']['StandardsControlArn'].split('/')[-2]}")
    end
  end
end

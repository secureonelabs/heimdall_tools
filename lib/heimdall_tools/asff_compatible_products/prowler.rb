module HeimdallTools
  class Prowler
    def self.subfindings_code_desc(finding, *, encode:, **)
      encode.call(finding['Description'])
    end

    def self.finding_id(finding, *, encode:, **)
      encode.call(finding['GeneratorId'].partition('-')[-1])
    end

    def self.product_name(findings, *, encode:, **)
      encode.call(findings[0]['ProductFields']['ProviderName'])
    end

    def self.desc(*, **)
      ' '
    end
  end
end

module HeimdallTools
  class FirewallManager
    def self.finding_id(finding, *, encode:, **)
      encode.call(finding['Title'])
    end

    def self.product_name(findings, *, encode:, **)
      encode.call("#{findings[0]['ProductFields']['aws/securityhub/CompanyName']} #{findings[0]['ProductFields']['aws/securityhub/ProductName']}")
    end
  end
end

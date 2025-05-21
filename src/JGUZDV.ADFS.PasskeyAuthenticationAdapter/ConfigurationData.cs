namespace JGUZDV.ADFS.PasskeyAuthenticationAdapter
{
    public class ConfigurationData
    {
        public string? PasskeyHandlerUrl { get; set; }

        public string? LdapServer { get; set; }
        public string? SearchBaseDN { get; set; }

        public string? DomainName { get; set; }
        public int LdapPort { get; set; } = 636;
    }
}

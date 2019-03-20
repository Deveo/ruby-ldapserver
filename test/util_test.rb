require File.dirname(__FILE__) + '/test_helper'
require 'ldap/server/util'

class TestLdapUtil < Test::Unit::TestCase
  def test_split_dn
    # examples from RFC 2253
    assert_equal(
	[{"cn"=>"Steve Kille"},{"o"=>"Isode Limited"},{"c"=>"GB"}],
	LDAP::Server::Operation.split_dn("CN=Steve Kille , O=Isode Limited;C=GB")
    )
    assert_equal(
	[{"ou"=>"Sales","cn"=>"J. Smith"},{"o"=>"Widget Inc."},{"c"=>"US"}],
	LDAP::Server::Operation.split_dn("OU=Sales+CN=J. Smith,O=Widget Inc.,C=US")
    )
    assert_equal(
	[{"cn"=>"L. Eagle"},{"o"=>"Sue, Grabbit and Runn"},{"c"=>"GB"}],
	LDAP::Server::Operation.split_dn("CN=L. Eagle,O=Sue\\, Grabbit and Runn,C=GB")
    )
    assert_equal(
	[{"cn"=>"Before\rAfter"},{"o"=>"Test"},{"c"=>"GB"}],
	LDAP::Server::Operation.split_dn("CN=Before\\0DAfter,O=Test,C=GB")
    )
    res = LDAP::Server::Operation.split_dn("SN=Lu\\C4\\8Di\\C4\\87")
    assert_equal([{ "sn" => "Lu\xc4\x8di\xc4\x87".force_encoding('ascii-8bit') }], res)

    # Just for fun, let's try parsing it as UTF8
    chars = res[0]["sn"].force_encoding('utf-8').scan(/./u)
    assert_equal(["L", "u", "\u010d", "i", "\u0107"], chars)
  end

  def test_join_dn
    # examples from RFC 2253
    assert_equal(
        "cn=Steve Kille,o=Isode Limited,c=GB",
	LDAP::Server::Operation.join_dn([{"cn"=>"Steve Kille"},{"o"=>"Isode Limited"},{"c"=>"GB"}])
    )
    # These are equivalent
    d1 = "ou=Sales+cn=J. Smith,o=Widget Inc.,c=US"
    d2 = "cn=J. Smith+ou=Sales,o=Widget Inc.,c=US"
    assert_equal(d1,
	LDAP::Server::Operation.join_dn([[["ou","Sales"],["cn","J. Smith"]],[["o","Widget Inc."]],["c","US"]])
    )
    r = LDAP::Server::Operation.join_dn([{"ou"=>"Sales","cn"=>"J. Smith"},{"o"=>"Widget Inc."},{"c"=>"US"}])
    assert(r == d1 || r == d2, "got #{r.inspect}, expected #{d1.inspect} or #{d2.inspect}")
    assert_equal(
	"cn=L. Eagle,o=Sue\\, Grabbit and Runn,c=GB",
	LDAP::Server::Operation.join_dn([{"cn"=>"L. Eagle"},{"o"=>"Sue, Grabbit and Runn"},{"c"=>"GB"}])
    )
  end
end


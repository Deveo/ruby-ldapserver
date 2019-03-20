require File.dirname(__FILE__) + '/test_helper'

Thread.abort_on_exception = true

# This test suite requires the ruby-ldap client library to be installed.
#
# Unfortunately, this library is not ruby thread-safe (it blocks until
# it gets a response). Hence we have to fork a child to perform the actual
# LDAP requests, which is nasty. However, it does give us a completely
# independent source of LDAP packets to try.

require 'ldap/server/operation'
require 'ldap/server/server'

require 'ldap'

# We subclass the Operation class, overriding the methods to do what we need

class MockOperation < LDAP::Server::Operation
  def initialize(connection, messageId)
    super(connection, messageId)
    @@lastop = [:connect]
  end

  def simple_bind(version, user, pass)
    @@lastop = [:simple_bind, version, user, pass]
  end

  def search(basedn, scope, deref, filter)
    @@lastop = [:search, basedn, scope, deref, filter, @attributes]
    send_SearchResultEntry("cn=foo", {"a"=>["1","2"], "b"=>"boing"})
    send_SearchResultEntry("cn=bar", {"a"=>["3","4","5"], "b"=>"wibble"})
  end

  def add(dn, av)
    @@lastop = [:add, dn, av]
  end

  def del(dn)
    @@lastop = [:del, dn]
  end

  def modify(dn, ops)
    @@lastop = [:modify, dn, ops]
  end

  def modifydn(dn, newrdn, deleteoldrdn, newSuperior)
    @@lastop = [:modifydn, dn, newrdn, deleteoldrdn, newSuperior]
  end

  def compare(dn, attr, val)
    @@lastop = [:compare, dn, attr, val]
    return val != "false"
  end

  def self.lastop
    @@lastop
  end
end

class TestLdap < Test::Unit::TestCase
  HOST = '127.0.0.1'
  PORT = 1389

  def open_child_posix
    IO.popen("-","w+").tap do |io|
      unless io
        do_child Kernel, Kernel
        exit!
      end
    end
  end

  class DoubleIO < IO
    def initialize out, inio
      @out_io = out
      @in_io = inio
    end

    def read *a
      @out_io.read *a
    end

    def write *a
      @in_io.write *a
    end

    def gets
      @out_io.gets
    end

    def close
      @in_io.close
      @out_io.close
    end
  end

  def open_child_java
    in_rd, in_wr = IO.pipe
    out_rd, out_wr = IO.pipe
    Thread.new do
      do_child in_rd, out_wr
    end
    DoubleIO.new(out_rd, in_wr)
  end

  def open_child
    case RUBY_PLATFORM
    when 'java'
      open_child_java
    else
      open_child_posix
    end
  end

  def setup
    @ppid = $$
    @io = open_child

    # back to a single process (the parent). Now we start our
    # listener thread
    @serv = LDAP::Server.new(
    	:bindaddr		=> '127.0.0.1',
    	:port			=> PORT,
    	:nodelay		=> true,
    	:operation_class	=> MockOperation
    )
    @serv.run_tcpserver
  end

  def teardown
    if @serv
      @serv.stop
      @serv = nil
    end
    if @io
      @io.puts "quit"
      @io.gets
      @io.close
      @io = nil
    end
  end

  # Process commands on stdin in child

  def do_child in_, out
    while true
      begin
        a = in_.gets.chomp
        conn ||= LDAP::Conn.new(HOST,PORT)
        case a
        when "bind2"
          conn.set_option(LDAP::LDAP_OPT_PROTOCOL_VERSION, 2)
          conn.bind("foo","bar")
        when "bind3"
          conn.set_option(LDAP::LDAP_OPT_PROTOCOL_VERSION, 3)
          conn.bind("foo","bar")
        # these examples taken from the ruby-ldap examples
        when "add1"
          entry1 = [
            LDAP.mod(LDAP::LDAP_MOD_ADD, 'objectclass', ['top', 'domain']),
            LDAP.mod(LDAP::LDAP_MOD_ADD, 'o', ['TTSKY.NET']),
            LDAP.mod(LDAP::LDAP_MOD_ADD, 'dc', ['localhost']),
          ]
          conn.add("dc=localhost, dc=domain", entry1)
        when "add2"
          entry2 = [
            LDAP.mod(LDAP::LDAP_MOD_ADD, 'objectclass', ['top', 'person']),
            LDAP.mod(LDAP::LDAP_MOD_ADD, 'cn', ['Takaaki Tateishi']),
            LDAP.mod(LDAP::LDAP_MOD_ADD | LDAP::LDAP_MOD_BVALUES, 'sn', ['ttate','Tateishi', "zero\000zero"]),
          ]
          conn.add("cn=Takaaki Tateishi, dc=localhost, dc=localdomain", entry2)
        when "del"
          conn.delete("cn=Takaaki-Tateishi, dc=localhost, dc=localdomain")
        when /^compare (.*)/
          begin
            case conn.compare("cn=Takaaki Tateishi, dc=localhost, dc=localdomain",
                         "cn", $1)
            when true; out.puts "OK true"; next
            when false; out.puts "OK false"; next
            end
          rescue LDAP::ResultError => e
            # For older versions of ruby-ldap
            case e.message
            when /Compare True/i; out.puts "OK true"; next
            when /Compare False/i; out.puts "OK false"; next
            end
            raise
          end
        when "modrdn"
          conn.modrdn("cn=Takaaki Tateishi, dc=localhost, dc=localdomain",
                      "cn=Takaaki-Tateishi",
                      true)
        when "modify"
          entry = [
            LDAP.mod(LDAP::LDAP_MOD_ADD, 'objectclass', ['top', 'domain']),
            LDAP.mod(LDAP::LDAP_MOD_DELETE, 'o', []),
            LDAP.mod(LDAP::LDAP_MOD_REPLACE, 'dc', ['localhost']),
          ]
          conn.modify("dc=localhost, dc=domain", entry)
        when "search"
          res = {}
          conn.search("dc=localhost, dc=localdomain",
                      LDAP::LDAP_SCOPE_SUBTREE,
                      "(objectclass=*)") do |e|
            entry = e.to_hash
            dn = entry.delete("dn").first
            res[dn] = entry
          end
          exp = {
            "cn=foo" => {"a"=>["1","2"], "b"=>["boing"]},
            "cn=bar" => {"a"=>["3","4","5"], "b"=>["wibble"]},
          }
          if res != exp
            raise "Bad Search Result, expected\n#{exp.inspect}\ngot\n#{res.inspect}"
          end
        when "search2"
          # FIXME: ruby-ldap doesn't seem to allow DEREF options to be set
          conn.search("dc=localhost, dc=localdomain",
                      LDAP::LDAP_SCOPE_BASE,
                      "(&(cn=foo)(objectclass=*)(|(!(sn=*))(ou>=baz)(o<=z)(cn~=brian)(cn=*and*er)))",
                      ["a","b"]) do |e|
            entry = e.to_hash
            dn = entry.delete("dn").first
            res[dn] = entry
          end
        when "search_retrieve_attrs"
          res = {}
          conn.search("dc=localhost, dc=localdomain",
                      LDAP::LDAP_SCOPE_SUBTREE,
                      "(objectclass=*)",
                      ["B"]) do |e|
            entry = e.to_hash
            dn = entry.delete("dn").first
            res[dn] = entry
          end
          exp = {
            "cn=foo" => {"b"=>["boing"]},
            "cn=bar" => {"b"=>["wibble"]},
          }
          if res != exp
            raise "Bad Search Result, expected\n#{exp.inspect}\ngot\n#{res.inspect}"
          end
        when "search_timeout"
          res = {}
          conn.set_option(LDAP::LDAP_OPT_TIMELIMIT, 2)
          conn.search("dc=localhost, dc=localdomain",
                      LDAP::LDAP_SCOPE_SUBTREE,
                      "(objectclass=*)") do |e|
            entry = e.to_hash
            dn = entry.delete("dn").first
            res[dn] = entry
          end
        when "quit"
          out.puts "OK"
          break
        else
          raise "Bad command! #{a.inspect}"
        end
        out.puts "OK"
      rescue Exception => e
        $stderr.puts "Child exception: #{e}\n\t#{e.backtrace.join("\n\t")}"
        out.puts "ERR #{e}"
      end
    end
  end

  def req(cmd)
    @io.puts cmd
    res = @io.gets.chomp
    assert_match(/^OK/, res)
    res
  end

  def test_bind2
    req("bind2")
    assert_equal([:simple_bind, 2, "foo", "bar"], MockOperation.lastop)
    # cannot bind any more; ldap client library says "already binded." (sic)
  end

  def test_bind3
    req("bind3")
    assert_equal([:simple_bind, 3, "foo", "bar"], MockOperation.lastop)
    # cannot bind any more; ldap client library says "already binded." (sic)
  end

  def test_add
    req("add1")
    assert_equal([:add, "dc=localhost, dc=domain", {
      'objectclass'=>['top', 'domain'],
      'o'=>['TTSKY.NET'],
      'dc'=>['localhost'],
    }], MockOperation.lastop)
    req("add2")
    assert_equal([:add, "cn=Takaaki Tateishi, dc=localhost, dc=localdomain", {
      'objectclass'=>['top', 'person'],
      'cn'=>['Takaaki Tateishi'],
      'sn'=>['ttate','Tateishi',"zero\000zero"],
    }], MockOperation.lastop)
  end

  def test_del
    req("del")
    assert_equal([:del, "cn=Takaaki-Tateishi, dc=localhost, dc=localdomain"], MockOperation.lastop)
  end

  def test_compare
    r = req("compare Takaaki Tateishi")
    assert_match(/OK true/, r)
    assert_equal([:compare, "cn=Takaaki Tateishi, dc=localhost, dc=localdomain",
      "cn", "Takaaki Tateishi"], MockOperation.lastop)
    r = req("compare false")
    assert_match(/OK false/, r)
    assert_equal([:compare, "cn=Takaaki Tateishi, dc=localhost, dc=localdomain",
      "cn", "false"], MockOperation.lastop)
  end

  def test_modrdn
    req("modrdn")
    assert_equal([:modifydn, "cn=Takaaki Tateishi, dc=localhost, dc=localdomain",
      "cn=Takaaki-Tateishi", true, nil], MockOperation.lastop)
    # FIXME: ruby-ldap doesn't support the four-argument form
  end

  def test_modify
    req("modify")
    assert_equal([:modify, "dc=localhost, dc=domain", {
        'objectclass' => [:add, 'top', 'domain'],
        'o' => [:delete],
        'dc' => [:replace, 'localhost'],
    }], MockOperation.lastop)
  end

  def test_search
    req("search")
    assert_equal([:search, "dc=localhost, dc=localdomain",
      LDAP::Server::WholeSubtree,
      LDAP::Server::NeverDerefAliases,
      [:true], []], MockOperation.lastop)
    req("search2")
    assert_equal([:search, "dc=localhost, dc=localdomain",
      LDAP::Server::BaseObject,
      LDAP::Server::NeverDerefAliases,
      [:and, [:eq, "cn", nil, "foo"],
             [:or,  [:not, [:present, "sn"]],
                    [:ge, "ou", nil, "baz"],
                    [:le, "o", nil, "z"],
                    [:approx, "cn", nil, "brian"],
                    [:substrings, "cn", nil, nil, "and", "er"],
             ],
      ], ["a","b"]], MockOperation.lastop)
  end

  def test_retrieve_attributes_case_insensitive
    req("search_retrieve_attrs")
    assert_equal([:search, "dc=localhost, dc=localdomain",
      LDAP::Server::WholeSubtree,
      LDAP::Server::NeverDerefAliases,
      [:true], ["B"]], MockOperation.lastop)
  end

  def test_search_client_timeout
    # Should not raise errors
    req("search_timeout")
    assert_equal([:search, "dc=localhost, dc=localdomain",
      LDAP::Server::WholeSubtree,
      LDAP::Server::NeverDerefAliases,
      [:true], []], MockOperation.lastop)
  end
end

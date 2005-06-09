#!/usr/local/bin/ruby -w

# A slightly more sophisticated example, which implements:
# - a base DN, and referrals if you try to search outside that DN
# - read-only access for anonymous, read-write for authorised user
# - indexing of certain attributes

$:.unshift('../lib')

require 'ldapserver/tcpserver'
require 'ldapserver/connection'
require 'ldapserver/operation'

# We subclass the Operation class, overriding the methods to do what we need

class HashOperation < LDAPserver::Operation
  def initialize(connection, messageID, hash)
    super(connection, messageID)
    @hash = hash   # our directory data
  end

  def search(basedn, scope, deref, filter, attrs)
    @hash.each do |dn, av|
      send_SearchResultEntry(dn, av)
    end
  end

  def add(dn, av)
    dn.downcase!
    raise LDAPserver::EntryAlreadyExists if @hash[dn]
    @hash[dn] = av
  end

  def del(dn)
    dn.downcase!
    raise LDAPserver::NoSuchObject unless @hash.has_key?(dn)
    @hash.delete(dn)
  end

  def modify(dn, ops)
    entry = @hash[dn]
    raise LDAPserver::NoSuchObject unless entry
    ops.each do |op, attr, vals|
      case op 
      when :add
        entry[attr] ||= []
        entry[attr] += vals
        entry[attr].uniq!
      when :delete
        if vals == []
          entry.delete(attr)
        else
          vals.each { |v| entry[attr].delete(v) }
          entry.delete(attr) if entry[attr] == {}
        end
      when :replace
        entry[attr] = vals
      end
    end
  end
end

# This is the shared object which carries our actual directory entries.
# It's just a hash of {dn=>entry}, where each entry is {attr=>[val,val,...]}

directory = {}

# Let's put some backing store on it

require 'yaml'
begin
  File.open("ldapdb.yaml") { |f| directory = YAML::load(f.read) }
rescue Errno::ENOENT
end

at_exit do
  File.open("ldapdb.new","w") { |f| f.write(YAML::dump(directory)) }
  File.rename("ldapdb.new","ldapdb.yaml")
end

# Listen for incoming LDAP connections. For each one, create a Connection
# object, which will invoke a HashOperation object for each request.

t = LDAPserver::tcpserver(:port=>1389) do
  LDAPserver::Connection::new(self).handle_requests(HashOperation, directory)
end
t.join
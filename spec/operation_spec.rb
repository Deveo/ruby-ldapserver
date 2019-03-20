require 'spec_helper'

require 'ldap/server/operation'

describe LDAP::Server::Operation do
  let(:server) { double 'server' }
  let(:connection) { double "connection", opt: { schema: schema, server: server } }
  let(:message_id) { 337 }
  subject(:operation) { LDAP::Server::Operation.new connection, message_id }

  context 'on search' do
    before do
      operation.instance_variable_set :@attributes, attributes
      operation.instance_variable_set :@rescount, 0
    end

    context 'with schema and wildcard attribute query' do
      let(:schema) do
        double('schema').tap do |schema|
          allow(schema).to receive(:find_attrtype).and_return nil
          allow(schema).to receive(:find_attrtype).with('attr')\
              .and_return double 'attr', usage: nil
        end
      end
      let(:attributes) { %w(*) }

      describe '#send_SearchResultEntry' do
        it 'correctly handles wildcard attribute' do
          expect(connection).to receive(:write).twice do |message|
            expect(message).to include 'val'
          end

          operation.send_SearchResultEntry 'o=foo', 'attr' => 'val'
          operation.send_SearchResultEntry 'o=bar', 'attr' => 'val'
        end
      end
    end
  end
end

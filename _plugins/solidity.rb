# _plugins/solidity.rb
require 'rouge'

module Rouge
  module Lexers
    class Solidity < RegexLexer
      title 'Solidity'
      desc 'Solidity smart contract language'
      tag 'solidity'
      filenames '*.sol'

      def self.keywords
        @keywords ||= Set.new %w(
          pragma solidity import contract interface library using is new delete
          function modifier constructor fallback receive event emit
          struct enum mapping returns return if else for while do break
          continue throw revert require assert try catch import as
          public private internal external pure view payable constant
          immutable override virtual abstract memory storage calldata
          indexed anonymous unchecked assembly
        )
      end

      def self.types
        @types ||= Set.new %w(
          address bool string bytes byte
          int int8 int16 int32 int64 int128 int256
          uint uint8 uint16 uint32 uint64 uint128 uint256
          bytes1 bytes2 bytes4 bytes8 bytes16 bytes32 fixed ufixed
        )
      end

      def self.builtins
        @builtins ||= Set.new %w(
          true false wei gwei ether seconds minutes hours days weeks
          msg block tx now this super keccak256 sha256 ecrecover
          selfdestruct addmod mulmod type abi
        )
      end

      state :root do
        rule %r/\s+/, Text::Whitespace
        rule %r(//.*?$), Comment::Single
        rule %r(/\*.*?\*/)m, Comment::Multiline
        rule %r/"/, Str::Double, :dq
        rule %r/'/, Str::Single, :sq
        rule %r/\b(0x[0-9a-fA-F]+|\d+(\.\d+)?)\b/, Num
        rule %r/[a-zA-Z_$]\w*/ do |m|
          name = m[0]
          if self.class.keywords.include?(name)
            token Keyword
          elsif self.class.types.include?(name)
            token Keyword::Type
          elsif self.class.builtins.include?(name)
            token Name::Builtin
          else
            token Name
          end
        end
        rule %r/[{}()\[\];,.]/, Punctuation
        rule %r([+\-*\/%=<>!&|\^~?:]), Operator
      end

      state :dq do
        rule %r/\\./, Str::Escape
        rule %r/"/, Str::Double, :pop!
        rule %r/[^"\\]+/, Str::Double
      end

      state :sq do
        rule %r/\\./, Str::Escape
        rule %r/'/, Str::Single, :pop!
        rule %r/[^'\\]+/, Str::Single
      end
    end
  end
end
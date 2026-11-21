class HttpRigSchema < GraphQL::Schema
  class << self
    attr_accessor :bumps, :reads
  end

  self.bumps = 0
  self.reads = 0

  class Query < GraphQL::Schema::Object
    field :ok, Boolean, null: false

    def ok
      HttpRigSchema.reads += 1

      true
    end
  end

  class Mutation < GraphQL::Schema::Object
    field :bump, Integer, null: false

    def bump
      HttpRigSchema.bumps += 1
    end
  end

  query Query
  mutation Mutation
end

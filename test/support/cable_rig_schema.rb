# Smallest schema that serves the encrypted socket with the stock graphql-ruby ActionCable transport.
class CableRigSchema < GraphQL::Schema
  class Subscriptions < GraphQL::Subscriptions::ActionCableSubscriptions
    def live
      @live ||= Set.new
    end

    def write_subscription(query, events)
      super.tap { live << query.context[:subscription_id] }
    end

    def delete_subscription(subscription_id)
      super.tap { live.delete(subscription_id) }
    end
  end

  class << self
    attr_accessor :on_subscribe

    def reset_hooks
      self.on_subscribe = nil
    end
  end

  class Query < GraphQL::Schema::Object
    field :ok, Boolean, null: false

    def ok
      true
    end
  end

  class Tick < GraphQL::Schema::Subscription
    field :value, String, null: false

    def subscribe
      CableRigSchema.on_subscribe&.call

      :no_response
    end

    def update
      { value: object.fetch(:value) }
    end
  end

  class Stop < GraphQL::Schema::Subscription
    field :value, String, null: false

    def subscribe
      :no_response
    end

    def update
      object[:final] ? unsubscribe({ value: 'last' }) : unsubscribe
    end
  end

  class Explode < GraphQL::Schema::Subscription
    field :value, String, null: false

    def subscribe
      context[:channel].stream_from('rig:leak') { |_message| nil }

      raise 'subscribe failed after stream_from'
    end
  end

  class Subscription < GraphQL::Schema::Object
    field :tick, subscription: Tick
    field :stop, subscription: Stop
    field :explode, subscription: Explode
  end

  query Query
  subscription Subscription
  use Subscriptions
end

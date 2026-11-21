class CableRigChannel < GraphqlEncrypted::Cable::Channel
  schema CableRigSchema
  session CableSession
end

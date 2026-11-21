class GraphqlEncrypted::Diagnostics::Redactor < GraphQL::Language::Printer
  def filtered?
    @filtered
  end

  protected

  def print_argument(argument)
    print_string(argument.name)
    print_string(': ')
    return print_node(argument.value) if argument.value.is_a?(GraphQL::Language::Nodes::VariableIdentifier)

    @filtered = true

    print_string(JSON.generate(GraphqlEncrypted::Diagnostics::FILTERED))
  end

  def print_variable_definition(variable_definition)
    print_string("$#{variable_definition.name}: ")
    print_node(variable_definition.type)
    unless variable_definition.default_value.nil?
      @filtered = true
      print_string(" = #{JSON.generate(GraphqlEncrypted::Diagnostics::FILTERED)}")
    end

    variable_definition.directives.each do |directive|
      print_string(' ')
      print_directive(directive)
    end
  end
end

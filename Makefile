all: rule_test add_table del_table add_chain del_chain

rule_test:
	g++ -o addrule_new -g addrule.cpp iptable_rule.cpp iptable_helpers.cpp rule_expression.cpp rule_expressions/payload_expression.cpp rule_expressions/log_expression.cpp rule_expressions/meta_expression.cpp rule_expressions/counter_expression.cpp rule_expressions/comparison_expression.cpp rule_expressions/reject_expression.cpp -lmnl

add_table:
	g++ -o addtable -g addtable.cpp -lmnl

add_chain:
	g++ -o addchain -g addchain.cpp -lmnl

del_table:
	g++ -o deltable -g deltable.cpp -lmnl

del_chain:
	g++ -o delchain -g delchain.cpp -lmnl
all: rule_test add_table del_table get_table add_chain get_chain del_chain

rule_test:
	g++ -o addrule -g addrule.cpp iptable_rule.cpp iptable_helpers.cpp rule_expression.cpp rule_expressions/payload_expression.cpp rule_expressions/log_expression.cpp rule_expressions/meta_expression.cpp rule_expressions/counter_expression.cpp rule_expressions/comparison_expression.cpp rule_expressions/reject_expression.cpp rule_expressions/match_expression.cpp rule_expressions/bitwise_expression.cpp netfilter_table_controller.cpp -lmnl

add_table:
	g++ -o addtable -g addtable.cpp iptable_helpers.cpp netfilter_table_controller.cpp

get_table:
	g++ -o gettable -g gettable.cpp iptable_helpers.cpp netfilter_table_controller.cpp 

add_chain:
	g++ -o addchain -g addchain.cpp iptable_helpers.cpp netfilter_table_controller.cpp

get_chain:
	g++ -o getchain -g getchain.cpp iptable_helpers.cpp netfilter_table_controller.cpp -lmnl

del_table:
	g++ -o deltable -g deltable.cpp iptable_helpers.cpp -lmnl

del_chain:
	g++ -o delchain -g delchain.cpp iptable_helpers.cpp -lmnl
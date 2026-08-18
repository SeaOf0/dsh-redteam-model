# 规则开发说明

### 规则文件的命名

* source类型_sink类型_漏洞类型.cypher

### 规则文件的语法

* 规则都是以cypher语句编写，规则文件可以包含多个cypher语句,参考 neo4j cypher语法即可

### 规则文件的编写案例

````
MATCH
(sourceNode:Argument)
WHERE
sourceNode.type = 'ObjectInputStream' AND
sourceNode.method = 'readObject'

MATCH
(sinkNode)
WHERE
// 命令执行
('exec' IN  sinkNode.selectors AND 'Runtime' IN  sinkNode.receiverTypes) OR
sinkNode.AllocationClassName = 'ProcessBuilder' OR
('command' IN sinkNode.selectors AND 'ProcessBuilder' IN sinkNode.receiverTypes) OR
//  反射调用
('forName' IN sinkNode.selectors AND 'Class' IN sinkNode.receiverTypes) OR
('invoke' IN sinkNode.selectors AND 'Method' IN sinkNode.receiverTypes)

MATCH
p = shortestPath((sourceNode)-[*..30]->(sinkNode))
WHERE none(n IN nodes(p)
WHERE n.type IS NOT NULL AND n.type IN ['Long', 'Integer', 'int', 'long'])
RETURN
p AS path

/*

漏洞描述（markdown 格式）


修复建议（markdown 格式）

*/
````

#!/usr/bin/env python3

import os
import re

from typing import List, Union, Optional, Iterable, Callable, cast, Any, Pattern

# These  names are just used in the constructors for these clasess
ElementList = Iterable[Union['Node', 'Property', 'Directive']]
DirectiveOption = List[Any]

# Callback isinstance signatures for Devicetree.match() and Devicetree.chosen()
MatchCallback = Optional[Callable[['Node'], None]]
ChosenCallback = Optional[Callable[['PropertyValues'], None]]

def formatLevel(level: int, s: str) -> str:
    return "\t" * level + s

def wrapStrings(values: List[Any], formatHex: bool = False) -> List[Any]:
    wrapped = []
    for v in values:
        if isinstance(v, str):
            if v[0] != '&':
                wrapped.append("\"%s\"" % v)
            else:
                wrapped.append(v)
        elif isinstance(v, int):
            if formatHex:
                wrapped.append("0x%x" % v)
            else:
                wrapped.append(str(v))
        else:
            wrapped.append(str(v))
    return wrapped

class PropertyValues:
    def __init__(self, values: List[Any] = None):
        self.values = values

    def __repr__(self) -> str:
        return "<PropertyValues " + self.values.__repr__() + ">"

    def __str__(self) -> str:
        return self.to_dts()

    def __iter__(self):
        return iter(self.values)

    def __len__(self) -> int:
        return len(self.values)

    def to_dts(self, formatHex: bool = False) -> str:
        return " ".join(wrapStrings(self.values, formatHex))

    def __getitem__(self, key) -> Any:
        return self.values[key]

    def __eq__(self, other) -> bool:
        if isinstance(other, PropertyValues):
            return self.values == other.values
        return self.values == other

class Bytestring(PropertyValues):
    def __init__(self, bytelist: List[int] = None):
        PropertyValues.__init__(self, bytearray(bytelist))

    def __repr__(self) -> str:
        return "<Bytestring " + str(self.values) + ">"

    def to_dts(self, formatHex: bool = False) -> str:
        return "[" + " ".join("%02x" % v for v in self.values) + "]"

class CellArray(PropertyValues):
    def __init__(self, cells: List[Any] = None):
        PropertyValues.__init__(self, cells)

    def __repr__(self) -> str:
        return "<CellArray " + self.values.__repr__() + ">"

    def to_dts(self, formatHex: bool = False) -> str:
        return "<" + " ".join(wrapStrings(self.values, formatHex)) + ">"

class StringList(PropertyValues):
    def __init__(self, strings: List[str] = None):
        PropertyValues.__init__(self, strings)

    def __repr__(self) -> str:
        return "<StringList " + self.values.__repr__() + ">"

    def to_dts(self, formatHex: bool = False) -> str:
        return ", ".join(wrapStrings(self.values))

class Property:
    def __init__(self, name: str, values: PropertyValues):
        self.name = name
        self.values = values

    def __repr__(self) -> str:
        return "<Property %s>" % self.name

    def __str__(self) -> str:
        return self.to_dts()

    def to_dts(self, level: int = 0) -> str:
        if self.name in ["reg", "ranges"]:
            value = self.values.to_dts(formatHex=True)
        else:
            value = self.values.to_dts(formatHex=False)

        if value != "":
            return formatLevel(level, "%s = %s;\n" % (self.name, value))
        return formatLevel(level, "%s;\n" % self.name)

class Directive:
    def __init__(self, directive: str, options: DirectiveOption = None):
        self.directive = directive
        self.options = options

    def __repr__(self) -> str:
        return "<Directive %s>" % self.directive

    def __str__(self) -> str:
        return self.to_dts()

    def to_dts(self, level: int = 0) -> str:
        if self.options:
            return formatLevel(level, "%s %s;\n" % (self.directive, self.options))
        return formatLevel(level, "%s;\n" % self.directive)

class Node:
    # pylint: disable=too-many-arguments
    def __init__(self, name: str, label: Optional[str] = None, address: Optional[str] = None,
                 properties: List[Property] = None, directives: List[Directive] = None,
                 children: List['Node'] = None):
        self.name = name
        self.parent = None # isinstance: Optional['Node']

        self.label = label
        self.address = address
        self.properties = properties
        self.directives = directives
        self.children = children

    def __repr__(self) -> str:
        if self.address:
            return "<Node %s@%s>" % (self.name, self.address)
        return "<Node %s>" % self.name

    def __str__(self) -> str:
        return self.to_dts()

    def to_dts(self, level: int = 0) -> str:
        out = ""
        if isinstance(self.address, int) and self.label:
            out += formatLevel(level,
                               "%s: %s@%x {\n" % (self.label, self.name, cast(int, self.address)))
        elif isinstance(self.address, int):
            out += formatLevel(level, "%s@%x {\n" % (self.name, cast(int, self.address)))
        elif self.label:
            out += formatLevel(level, "%s: %s {\n" % (self.label, self.name))
        elif self.name != "":
            out += formatLevel(level, "%s {\n" % self.name)

        for d in self.directives:
            out += d.to_dts(level + 1)
        for p in self.properties:
            out += p.to_dts(level + 1)
        for c in self.children:
            out += c.to_dts(level + 1)

        if self.name != "":
            out += formatLevel(level, "};\n")

        return out

    def child_nodes(self) -> Iterable['Node']:
        for n in self.children:
            yield n
            for m in n.child_nodes():
                yield m

    def get_fields(self, field_name: str) -> Optional[PropertyValues]:
        for p in self.properties:
            if p.name == field_name:
                return p.values
        return None

    def get_field(self, field_name: str) -> Any:
        fields = self.get_fields(field_name)
        if fields is not None:
            if len(cast(PropertyValues, fields)) != 0:
                return fields[0]
        return None

    def address_cells(self):
        cells = self.get_field("#address-cells")
        if cells is not None:
            return cells
        if self.parent is not None:
            return self.parent.address_cells()
        # No address cells found
        return 0

    def size_cells(self):
        cells = self.get_field("#size-cells")
        if cells is not None:
            return cells
        if self.parent is not None:
            return self.parent.size_cells()
        # No size cells found
        return 0

class Devicetree(Node):
    def __init__(self, elements: ElementList = None):
        properties = [] # type: List[Property]
        directives = [] # type: List[Directive]
        children = [] # type: List[Node]

        for e in elements:
            if isinstance(e, Node):
                children.append(cast(Node, e))
            elif isinstance(e, Property):
                properties.append(cast(Property, e))
            elif isinstance(e, Directive):
                directives.append(cast(Directive, e))

        Node.__init__(self, name="",
                      properties=properties, directives=directives, children=children)

    def __repr__(self) -> str:
        name = self.root().get_field("compatible")
        return "<Devicetree %s>" % name

    def to_dts(self, level: int = 0) -> str:
        out = ""

        for d in self.directives:
            out += d.to_dts()
        for p in self.properties:
            out += p.to_dts()
        for c in self.children:
            out += c.to_dts()

        return out

    @staticmethod
    def parseFile(filename: str, followIncludes: bool = False) -> 'Devicetree':
        # pylint: disable=import-outside-toplevel,cyclic-import
        from pydevicetree.source import parseTree
        with open(filename, 'r') as f:
            contents = f.read()
        pwd = os.path.dirname(filename) + "/"
        return parseTree(contents, pwd, followIncludes)

    def all_nodes(self) -> Iterable[Node]:
        return self.child_nodes()

    def root(self) -> Node:
        for n in self.all_nodes():
            if n.name == "/":
                return n
        raise Exception("Devicetree has no root node!")

    def match(self, compatible: Pattern, func: MatchCallback = None) -> List[Node]:
        regex = re.compile(compatible)

        def match_compat(node: Node) -> bool:
            compatibles = node.get_fields("compatible")
            if compatibles is not None:
                return any(regex.match(c) for c in compatibles)
            return False

        nodes = list(filter(match_compat, self.all_nodes()))

        if func is not None:
            for n in nodes:
                func(n)

        return nodes

    def chosen(self, property_name: str, func: ChosenCallback = None) -> Optional[PropertyValues]:
        def match_chosen(node: Node) -> bool:
            return node.name == "chosen"

        for n in filter(match_chosen, self.all_nodes()):
            for p in n.properties:
                if p.name == property_name:
                    if func is not None:
                        func(p.values)
                    return p.values

        return None
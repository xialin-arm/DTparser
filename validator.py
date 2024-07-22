import sys
from cot_parser import *

def main(input, output=None):
    cot = COT(input, output)
    cot.generate_c_file()

def parse(input):
    tree = Devicetree.parseFile(input)
    print(tree)

if __name__=="__main__":
    # main("cca.dtsi")
    # main("cca.dtsi", "test.c")
    # main("tbbr.dtsi")
    # parse("fvp-base-psci-common.dtsi")
    parse("fvp-base-gicv3.dtsi")
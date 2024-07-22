import sys
import re
from pydevicetree import *

def extractNumber(s):
    for i in s:
        if i.isdigit():
            return (int)(i)

    return -1

def removeNumber(s):
    result = ''.join([i for i in s if not i.isdigit()])
    return result

def parseBraces(line, braces):
    if len(braces) == 1 and braces[0] == "{" and "{" in line:
        return False

    if "{" in line:
        braces.append("{")
    elif "}" in line:
        if braces[-1] != "{":
            print("invalid brackets")
            exit(1)
        else:
            braces.pop()
            if (len(braces) == 0):
                return True

    return False

class COT:
    def __init__(self, inputfile: str, outputfile=None):
        self.tree = Devicetree.parseFile(inputfile)
        self.output = outputfile
        self.input = inputfile
        # self.parse_ifdef()
        # self.assign_ifdef()
    
    def get_ifdef(self, node:Node) -> list[str]:
        return node.ifdef

    def assign_ifdef(self):
        print(self.ifdef)
        return

    def if_root(self, node:Node) -> bool:
        for p in node.properties:
            if p.name == "root-certificate":
                return True
        return False
    
    def get_sign_key(self, node:Node):
        for p in node.properties:
            if p.name == "signing-key":
                return p.values
            
        return None
    
    def get_nv_ctr(self, node:Node):
        for nv in node.properties:
            if nv.name == "antirollback-counter":
                return nv.values
            
        return None
    
    def get_auth_data(self, node:Node):
        return node.children
    
    def format_auth_data_val(self, node:Node):
        type_desc = node.name
        if "sp_pkg" in type_desc:
            type_desc = removeNumber(type_desc)
        ptr = type_desc + "_buf"
        len = "(unsigned int)HASH_DER_LEN"
        if "pk" in type_desc:
            len = "(unsigned int)PK_DER_LEN"
        
        return type_desc, ptr, len

    def get_node(self, nodes: list[Node], name: str) -> Node:
        for i in nodes:
            if i.name == name:
                return i

    def get_certificates(self) -> Node:
        children = self.tree.children
        for i in children:
            if i.name == "cot":
                return self.get_node(i.children, "manifests")
            
    def get_images(self)-> Node:
        children = self.tree.children
        for i in children:
            if i.name == "cot":
                return self.get_node(i.children, "images")

    def get_nv_counters(self) -> Node:
        children = self.tree.children
        return self.get_node(children, "non_volatile_counters")

    def get_rot_keys(self) -> Node:
        children = self.tree.children
        return self.get_node(children, "rot_keys")

    def get_all_certificates(self) -> Node:
        cert = self.get_certificates()
        return cert.children

    def get_all_images(self) -> Node:
        image = self.get_images()
        return image.children

    def get_all_nv_counters(self) -> Node:
        nv = self.get_nv_counters()
        return nv.children

    def get_all_pks(self) -> Node:
        pk = self.get_rot_keys()
        if not pk:
            return []
        return pk.children
    
    def validate_cert(self, node:Node) -> bool:
        valid = True
        if not node.has_field("image-id"):
            valid = False
        
        if not node.has_field("root-certificate"):
            if not node.has_field("parent"):
                valid = False

        child = node.children
        if child:
            for c in child:
                if not c.has_field("oid"):
                    valid = False

        return valid
    
    def validate_img(self, node:Node) -> bool:
        valid = True
        if not node.has_field("image-id"):
            valid = False
        
        if not node.has_field("parent"):
            valid = False
        
        if not node.has_field("hash"):
            valid = False

        return valid

    def validate_nodes(self) -> bool:
        valid = True

        certs = self.get_all_certificates()
        images = self.get_all_images()

        for n in certs:
            node_valid = self.validate_cert(n)
            valid = valid and node_valid

        for i in images:
            node_valid = self.validate_img(i)
            valid = valid and node_valid

        print(valid)

        return valid
    
    # def images(self, filename, stack, ifdef):
    #     braces = ["{"]

    #     reg = re.compile(r'([\w]+) *{')
    #     imgNamereg = re.compile(r'([a-zA-Z0-9_]+)')
    #     ifdefregex = re.compile(r'#if defined *\(([\w]+)\)')
    #     ifdefend = "#endif"


    #     for line in filename:
    #         match = reg.search(line)
    #         match1 = imgNamereg.search(line)

    #         if match != None:
    #             imageName = match.groups()[0]
    #             ifdef[imageName] = stack.copy()

    #         elif match1 != None:
    #             imageName = match1.groups()[0]
    #             peekNextLine = True

    #         elif peekNextLine:
    #             peekNextLine = False
    #             if "{" in line:
    #                 ifdef[imageName] = stack.copy()

    #         match = ifdefregex.search(line)
    #         if match != None:
    #             stack.append(match.groups()[0])

    #         if ifdefend in line:
    #             stack.pop()

    #         if parseBraces(line, braces):
    #             return

    #     return

    # def manifest(self, filename, stack, ifdef):
    #     braces = ["{"]

    #     reg = re.compile(r'([\w]+) *: *([\w]+)')
    #     ifdefregex = re.compile(r'#if defined *\(([\w]+)\)')
    #     ifdefend = "#endif"


    #     for line in filename:
    #         match = reg.search(line)

    #         if match != None:
    #             imageName = match.groups()[0]
    #             ifdef[imageName] = stack.copy()

    #         match = ifdefregex.search(line)
    #         if match != None:
    #             stack.append(match.groups()[0])

    #         if ifdefend in line:
    #             stack.pop()

    #         if parseBraces(line, braces):
    #             return

    #     return

    # def parse_ifdef(self):
    #     ifdef = {}
    #     stack = []

    #     filename = open(self.input)

    #     ifdefregex = re.compile(r'#if defined *\(([\w]+)\)')
    #     ifdefend = "#endif"

    #     for line in filename:
    #         if "images" in line:
    #             self.images(filename, stack, ifdef)
    #             continue

    #         if "manifests" in line:
    #             self.manifest(filename, stack, ifdef)
    #             continue

    #         match = ifdefregex.search(line)
    #         if match != None:
    #             stack.append(match.groups()[0])

    #         if ifdefend in line:
    #             stack.pop()

    #     self.ifdef = ifdef
    #     return
    
    def extract_licence(self, f):
        licence = []

        licencereg = re.compile(r'/\*')
        licenceendReg = re.compile(r'\*/')

        licencePre = False

        for line in f:
            match = licencereg.search(line)
            if match != None:
                licence.append(line)
                licencePre = True
                continue

            match = licenceendReg.search(line)
            if match != None:
                licence.append(line)
                licencePre = False
                return licence

            if licencePre:
                licence.append(line)
            else:
                return licence
        
        return licence
    
    def licence_to_c(self, licence, f):
        if len(licence) != 0:
            for i in licence:
                f.write(i)

        f.write("\n")
        return
    
    def extract_include(self, f):
        include = []

        for line in f:
            if "cot" in line:
                return include

            if line != "" and "common" not in line and line != "\n":
                include.append(line)

        return include
    
    def include_to_c(self, include, f):
        f.write("#include <stddef.h>\n")
        f.write("#include <mbedtls/version.h>\n")
        f.write("#include <common/tbbr/cot_def.h>\n")
        f.write("#include <drivers/auth/auth_mod.h>\n")
        f.write("\n")
        for i in include:
            f.write(i)
        f.write("\n")
        f.write("#include <platform_def.h>\n\n")
        return

    def generate_header(self, input, output):
        licence = self.extract_licence(input)
        include = self.extract_include(input)
        self.licence_to_c(licence, output)
        self.include_to_c(include, output)

    def all_cert_to_c(self, f):
        certs = self.get_all_certificates()
        for c in certs:
            self.cert_to_c(c, f)

        f.write("\n")

    def cert_to_c(self, node: Node, f):
        ifdef = node.get_fields("ifdef")
        if ifdef:
            for i in ifdef:
                f.write("{}\n".format(i))

        f.write("static const auth_img_desc_t {} = {{\n".format(node.name))
        f.write("\t.img_id = {},\n".format(node.get_field("image-id").values[0].replace('"', "")))
        f.write("\t.img_type = IMG_CERT,\n")

        if not self.if_root(node):
            f.write("\t.parent = &{},\n".format(node.get_field("parent").label.name))
        else:
            f.write("\t.parent = NULL,\n")

        sign = self.get_sign_key(node)
        nv_ctr = self.get_nv_ctr(node)
        
        if sign or nv_ctr:
            f.write("\t.img_auth_methods = (const auth_method_desc_t[AUTH_METHOD_NUM]) {\n")
            
        if sign:
            f.write("\t\t[0] = {\n")
            f.write("\t\t\t.type = AUTH_METHOD_SIG,\n")
            f.write("\t\t\t.param.sig = {\n")

            f.write("\t\t\t\t.pk = &{},\n".format(sign))
            f.write("\t\t\t\t.sig = &sig,\n")
            f.write("\t\t\t\t.alg = &sig_alg,\n")
            f.write("\t\t\t\t.data = &raw_data\n")
            f.write("\t\t\t}\n")
            f.write("\t\t}}{}\n".format("," if nv_ctr else ""))

        if nv_ctr:
            f.write("\t\t[1] = {\n")
            f.write("\t\t\t.type = AUTH_METHOD_NV_CTR,\n")
            f.write("\t\t\t.param.nv_ctr = {\n")

            f.write("\t\t\t\t.cert_nv_ctr = &{},\n".format(nv_ctr))
            f.write("\t\t\t\t.plat_nv_ctr = &{}\n".format(nv_ctr))
            
            
            f.write("\t\t\t}\n")
            f.write("\t\t}\n")

        f.write("\t}\n")

        auth_data = self.get_auth_data(node)
        if auth_data:
            f.write("\t.authenticated_data = (const auth_param_desc_t[COT_MAX_VERIFIED_PARAMS]) {\n")

            for i, d in enumerate(auth_data):
                type_desc, ptr, data_len = self.format_auth_data_val(d)

                f.write("\t\t[{}] = {{\n".format(i))
                f.write("\t\t\t.type_desc = &{},\n".format(type_desc))
                f.write("\t\t\t.data = {\n")

                n = extractNumber(type_desc)
                if "pkg" not in type_desc or n == -1:
                    f.write("\t\t\t\t.ptr = (void *){},\n".format(ptr))
                else:
                    f.write("\t\t\t\t.ptr = (void *){}[{}],\n".format(ptr, n-1))

                f.write("\t\t\t\t.len = {}\n".format(data_len))
                f.write("\t\t\t}\n")

                f.write("\t\t}}{}\n".format("," if i != len(auth_data) - 1 else ""))

            f.write("\t}\n")

        f.write("};\n\n")

        if ifdef:
            for i in ifdef:
                f.write("#endif\n")
            f.write("\n")

        return


    def img_to_c(self, node:Node, f):
        ifdef = node.get_fields("ifdef")
        if ifdef:
            for i in ifdef:
                f.write("{}\n".format(i))

        f.write("static const auth_img_desc_t {} = {{\n".format(node.name))
        f.write("\t.img_id = {},\n".format(node.get_field("image-id").values[0].replace('"', "")))
        f.write("\t.img_type = IMG_RAW,\n")
        f.write("\t.parent = &{},\n".format(node.get_field("parent").label.name))
        f.write("\t.img_auth_methods = (const auth_method_desc_t[AUTH_METHOD_NUM]) {\n")

        f.write("\t\t[0] = {\n")
        f.write("\t\t\t.type = AUTH_METHOD_HASH,\n")
        f.write("\t\t\t.param.hash = {\n")
        f.write("\t\t\t\t.data = &raw_data,\n")
        f.write("\t\t\t\t.hash = &{}\n".format(node.get_field("hash").label.name))
        f.write("\t\t\t}\n")

        f.write("\t\t}\n")
        f.write("\t}\n")
        f.write("}\n\n")  

        if ifdef:
            for i in ifdef:
                f.write("#endif\n")
            f.write("\n")

        return

    def all_img_to_c(self, f):
        images = self.get_all_images()
        for i in images:
            self.img_to_c(i, f)

        f.write("\n")

    def nv_to_c(self, f):
        nv_ctr = self.get_all_nv_counters()

        for nv in nv_ctr:
            f.write("static auth_param_type_desc_t {} = AUTH_PARAM_TYPE_DESC(AUTH_PARAM_NV_CTR, {});\n".format(nv.name, nv.get_field("oid")))
        
        f.write("\n")

        return

    def pk_to_c(self, f):
        pks = self.get_all_pks()

        for p in pks:
            f.write("static auth_param_type_desc_t {} = AUTH_PARAM_TYPE_DESC(AUTH_PARAM_PUB_KEY, {});\n".format(p.name, p.get_field("oid")))

        f.write("\n")
        return

    def buf_to_c(self, f):
        certs = self.get_all_certificates()

        buffers = {}

        for c in certs:
            auth_data = self.get_auth_data(c)
            for a in auth_data:
                type_desc, ptr, data_len = self.format_auth_data_val(a)
                if ptr not in buffers:
                    buffers[ptr] = c.get_fields("ifdef")

        for key, values in buffers.items():
            if values:
                for i in values:
                    f.write("{}\n".format(i))

            if "sp_pkg_hash_buf" in key:
                f.write("static unsigned char {}[MAX_SP_IDS][HASH_DER_LEN];\n".format(key))
            elif "pk" in key:
                f.write("static unsigned char {}[PK_DER_LEN];\n".format(key))
            else:
                f.write("static unsigned char {}[HASH_DER_LEN];\n".format(key))

            if values:
                for i in values:
                    f.write("#endif\n")

        f.write("\n")

    def param_to_c(self, f):
        f.write("static auth_param_type_desc_t subject_pk = AUTH_PARAM_TYPE_DESC(AUTH_PARAM_PUB_KEY, 0);\n")
        f.write("static auth_param_type_desc_t sig = AUTH_PARAM_TYPE_DESC(AUTH_PARAM_SIG, 0);\n")
        f.write("static auth_param_type_desc_t sig_alg = AUTH_PARAM_TYPE_DESC(AUTH_PARAM_SIG_ALG, 0);\n")
        f.write("static auth_param_type_desc_t raw_data = AUTH_PARAM_TYPE_DESC(AUTH_PARAM_RAW_DATA, 0);\n")
        f.write("\n")

        certs = self.get_all_certificates()
        for c in certs:
            ifdef = c.get_fields("ifdef")
            if ifdef:
                for i in ifdef:
                    f.write("{}\n".format(i))

            hash = c.children
            for h in hash:
                name = h.name
                oid = h.get_field("oid")

                if "pk" in name and "pkg" not in name:
                    f.write("static auth_param_type_desc_t {} = "\
                        "AUTH_PARAM_TYPE_DESC(AUTH_PARAM_PUB_KEY, {});\n".format(name, oid))
                elif "hash" in name:
                    f.write("static auth_param_type_desc_t {} = "\
                            "AUTH_PARAM_TYPE_DESC(AUTH_PARAM_HASH, {});\n".format(name, oid))
                elif "ctr" in name:
                    f.write("static auth_param_type_desc_t {} = "\
                            "AUTH_PARAM_TYPE_DESC(AUTH_PARAM_NV_CTR, {});\n".format(name, oid))

            if ifdef:
                for i in ifdef:
                    f.write("#endif\n")

        f.write("\n")

    def cot_to_c(self, f):
        certs = self.get_all_certificates()
        images = self.get_all_images()

        f.write("static const auth_img_desc_t * const cot_desc[] = {\n")

        for i, c in enumerate(certs):
            ifdef = c.get_fields("ifdef")
            if ifdef:
                for i in ifdef:
                    f.write("{}\n".format(i))

            f.write("\t[{}]	=	&{}{}\n".format(c.get_field("image-id"), c.name, ","))

            if ifdef:
                for i in ifdef:
                    f.write("#endif\n")

        for i, c in enumerate(images):
            ifdef = c.get_fields("ifdef")
            if ifdef:
                for i in ifdef:
                    f.write("{}\n".format(i))

            f.write("\t[{}]	=	&{}{}\n".format(c.get_field("image-id"), c.name, "," if i != len(images) - 1 else ""))

            if ifdef:
                for i in ifdef:
                    f.write("#endif\n")

        f.write("};\n\n")
        f.write("REGISTER_COT(cot_desc);\n")
        return

    def generate_c_file(self):
        output = open(self.output, 'w+')
        input = open(self.input, "r")
        self.generate_header(input, output)
        self.buf_to_c(output)
        self.param_to_c(output)
        self.nv_to_c(output)
        self.pk_to_c(output)
        self.all_cert_to_c(output)
        self.all_img_to_c(output)
        self.cot_to_c(output)

        return
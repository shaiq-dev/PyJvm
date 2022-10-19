import sys
import io


class Constants:
    CLASS = 7
    FIELD_REF = 9
    METHOD_REF = 10
    INTERFACE_METHOD_REF = 11
    STRING = 8
    INTEGER = 3
    FLOAT = 4
    LONG = 5
    DOUBLE = 6
    NAME_AND_TYPE = 12
    UTF8 = 1
    METHOD_HANDLE = 15
    METHOD_TYPE = 16
    INVOKE_DYNAMIC = 18


class OpCodes:
    GET_STATIC = 0xB2
    LDC = 0x12
    INVOKE_VIRTUAL = 0xB6
    RETURN = 0xB1
    BI_PUSH = 0x10


CLASS_ACCESS_FLAGS = [
    ("ACC_PUBLIC", 0x0001),
    ("ACC_FINAL", 0x0010),
    ("ACC_SUPER", 0x0020),
    ("ACC_INTERFACE", 0x0200),
    ("ACC_ABSTRACT", 0x0400),
    ("ACC_SYNTHETIC", 0x1000),
    ("ACC_ANNOTATION", 0x2000),
    ("ACC_ENUM", 0x4000)
]

METHOD_ACCESS_FLAGS = [
    ("ACC_PUBLIC", 0x0001),
    ("ACC_PRIVATE", 0x0002),
    ("ACC_PROTECTED", 0x0004),
    ("ACC_STATIC", 0x0008),
    ("ACC_FINAL", 0x0010),
    ("ACC_SYNCHRONIZED", 0x0020),
    ("ACC_BRIDGE", 0x0040),
    ("ACC_VARARGS", 0x0080),
    ("ACC_NATIVE", 0x0100),
    ("ACC_ABSTRACT", 0x0400),
    ("ACC_STRICT", 0x0800),
    ("ACC_SYNTHETIC", 0x1000),
]


def parse_flags(value: int, flags: [(str, int)]) -> [str]:
    return [name for (name, mask) in flags if (value & mask) != 0]


def parse_u(f, n): return int.from_bytes(f.read(n), 'big')


def parse_attributes(f, count):
    '''
    Attributes
        u2 - attribute_name_index
        u4 - attribute_length
        u1 - info[attribute_length]
    '''
    attributes = []
    for j in range(count):

        attribute = {}
        attribute['attribute_name_index'] = parse_u(f, 2)
        attribute_length = parse_u(f, 4)
        attribute['info'] = f.read(attribute_length)
        attributes.append(attribute)
    return attributes


def parse_class_file(file_path: str):
    with open(file_path, "rb") as f:
        clazz = {}
        clazz['magic'] = hex(parse_u(f, 4))
        clazz['minor'] = parse_u(f, 2)
        clazz['major'] = parse_u(f, 2)
        constant_pool_count = parse_u(f, 2)
        constant_pool = []

        for i in range(constant_pool_count - 1):
            cp_info = {}
            tag = parse_u(f, 1)

            if tag == Constants.METHOD_REF:
                cp_info['tag'] = 'CONSTANT_Methodref'
                cp_info['class_index'] = parse_u(f, 2)
                cp_info['name_and_type_index'] = parse_u(f, 2)

            if tag == Constants.CLASS:
                cp_info['tag'] = 'CONSTANT_Class'
                cp_info['name_index'] = parse_u(f, 2)

            if tag == Constants.NAME_AND_TYPE:
                cp_info['tag'] = 'CONSTANT_NameAndType'
                cp_info['name_index'] = parse_u(f, 2)
                cp_info['descriptor_index'] = parse_u(f, 2)

            if tag == Constants.UTF8:
                cp_info['tag'] = 'CONSTANT_Utf8'
                length = parse_u(f, 2)
                cp_info['bytes'] = f.read(length)

            if tag == Constants.FIELD_REF:
                cp_info['tag'] = 'CONSTANT_Fieldref'
                cp_info['class_index'] = parse_u(f, 2)
                cp_info['name_and_type_index'] = parse_u(f, 2)

            if tag == Constants.STRING:
                cp_info['tag'] = 'CONSTANT_String'
                cp_info['string_index'] = parse_u(f, 2)

            if not cp_info:
                raise NotImplementedError(
                    f"Unexpected constant tag \"{tag}\" in class file {file_path}")

            constant_pool.append(cp_info)

        clazz['constant_pool'] = constant_pool
        clazz['access_flags'] = parse_flags(parse_u(f, 2), CLASS_ACCESS_FLAGS)
        clazz['this_class'] = parse_u(f, 2)
        clazz['super_class'] = parse_u(f, 2)

        interfaces_count = parse_u(f, 2)
        interfaces = []
        for i in range(interfaces_count):
            raise NotImplementedError("Interfaces are not supported :(")
        clazz['interfaces'] = interfaces

        fields_count = parse_u(f, 2)
        fields = []
        for i in range(fields_count):
            raise NotImplementedError("Fields are not supported :(")
        clazz['fields'] = fields

        methods_count = parse_u(f, 2)
        methods = []
        for i in range(methods_count):
            method = {}
            method['access_flags'] = parse_flags(
                parse_u(f, 2), METHOD_ACCESS_FLAGS)
            method['name_index'] = parse_u(f, 2)
            method['descriptor_index'] = parse_u(f, 2)
            attributes_count = parse_u(f, 2)
            method['attributes'] = parse_attributes(f, attributes_count)
            methods.append(method)
        clazz['methods'] = methods

        attributes_count = parse_u(f, 2)
        clazz['attributes'] = parse_attributes(f, attributes_count)

        return clazz


def find_methods_by_name(clazz, name: bytes):
    return [method
            for method in clazz['methods']
            if clazz['constant_pool'][method['name_index'] - 1]['bytes'] == name]


def find_attributes_by_name(clazz, attributes, name: bytes):
    return [attr
            for attr in attributes
            if clazz['constant_pool'][attr['attribute_name_index'] - 1]['bytes'] == name]


def parse_code_attrs(info: bytes):
    attrs = {}
    with io.BytesIO(info) as f:
        attrs['max_stack'] = parse_u(f, 2)
        attrs['max_locals'] = parse_u(f, 2)
        code_length = parse_u(f, 4)
        attrs['code'] = f.read(code_length)
        exception_table_length = parse_u(f, 2)

        return attrs


if __name__ == '__main__':
    program, *args = sys.argv
    file_path, *args = args
    clazz = parse_class_file(file_path)
    print(clazz)

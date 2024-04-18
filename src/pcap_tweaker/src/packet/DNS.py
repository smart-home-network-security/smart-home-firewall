import random
import scapy.all as scapy
from scapy.layers import dns
from packet.Packet import Packet

class DNS(Packet):

    # Class variables
    name = "DNS"
    qtypes = [
        1,   # A
        2,   # NS
        3,   # MD
        4,   # MF
        5,   # CNAME
        6,   # SOA
        7,   # MB
        8,   # MG
        9,   # MR
        10,  # NULL
        11,  # WKS
        12,  # PTR
        13,  # HINFO
        14,  # MINFO
        15,  # MX
        16,  # TXT
        28,  # AAAA
        41,  # OPT
        255  # ANY
    ]

    # Modifiable fields
    fields = [
        "qr",
        "qtype",
        "qname"
    ]


    @staticmethod
    def iter_question_records(question_records: dns.DNSQRField) -> iter:
        """
        Iterate over question records.

        :param question_records: List of question records.
        :return: Iterator over question records.
        """
        layer_idx = 0
        question_record = question_records.getlayer(layer_idx)
        while question_record is not None:
            yield question_record
            layer_idx += 1
            question_record = question_records.getlayer(layer_idx)

    
    def get_field(self) -> str:
        """
        Randomly pick a DNS field to be modified.

        :return: Field name.
        """
        return random.choice(self.fields)


    def tweak(self) -> dict:
        """
        Randomly edit one DNS field, among the following:
            - QR flag
            - Query type
            - Query name

        :return: Dictionary containing tweak information.
        """
        # Store old hash value
        old_hash = self.get_hash()
        # Get field which will be modified
        field = self.get_field()
        
        # Get auxiliary fields
        qdcount = self.layer.getfieldval("qdcount")
        question_records = self.layer.getfieldval("qd") if qdcount > 0 else None

        # Initialize old and new values
        old_value = None
        new_value = None
        
        # Field is QR flag
        if field == "qr":
            # Flip QR flag value
            old_value = self.layer.getfieldval("qr")
            new_value = int(not old_value)
            self.layer.setfieldval("qr", new_value)
        
        # Field is query type
        elif field == "qtype" and question_records is not None:
            old_value = question_records.getfieldval("qtype")
            # Randomly pick new query type
            new_value = old_value
            while new_value == old_value:
                new_value = random.choice(self.qtypes)
            question_records.setfieldval("qtype", new_value)
        
        # Field is query name
        elif field == "qname" and question_records is not None:
            old_value = ""
            new_value = ""
            for question_record in DNS.iter_question_records(question_records):
                if old_value != "":
                    old_value += " + "
                old_value_single = question_record.getfieldval("qname")
                old_value += old_value_single.decode("utf-8")
                suffix = old_value_single[-1]
                old_value_trimmed = old_value_single[:-1]
                # Randomly change one character in query name
                new_value_trimmed = old_value_trimmed
                while new_value_trimmed == old_value_trimmed:
                    new_value_trimmed = Packet.bytes_edit_char(old_value_trimmed)
                new_value_single = new_value_trimmed + bytes(chr(suffix), "utf-8")
                if new_value != "":
                    new_value += " + "
                new_value += new_value_single.decode("utf-8")
                question_record.setfieldval("qname", new_value_single)
        
        # Update checksums
        self.update_fields()

        # Return value: dictionary containing tweak information
        return self.get_dict_log(field, old_value, new_value, old_hash)

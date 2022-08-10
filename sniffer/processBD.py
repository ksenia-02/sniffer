import psycopg2
from psycopg2 import Error
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from datetime import datetime


class ServiceBD:

    def __init__(self):
        try:
            self.connection = psycopg2.connect(user="postgres",
                                               password="12345678",
                                               port = "5432",
                                               database="sniff_bd")
            # Курсор для выполнения операций с базой данных
            self.cursor = self.connection.cursor()
            print("Успешно!")
        except(Exception, Error) as error:
            print("Ошибка при работе с PostgreSQL", error)
        finally:
            if self.connection:
                self.cursor.close()
                self.connection.close()
                print("Соединение с PostgreSQL закрыто")

    def __insert_data(self, table, name_col, values):
        self.cursor.execute(f"INSERT INTO {table} ({name_col} VALUES ({values})) ")

    def insert_ethernet_frame(self, values:tuple):
        self.__insert_data("ethernet_frame",
                           "destination, source, protocol, date_, time_",
                           (values[0], values[1], values[2], datetime.today(), datetime.now().time()))

    def insert_ipv4(self, values):
        self.__insert_data("ipv4_package",
                           "version, len_head, ttl, proto, src,target, data, date_, time_",
                           (values[0], values[1], values[2], values[3], values[4], values[5], values[6],
                            datetime.today(), datetime.now().time()))

    def insert_tcp(self, values):
        self.__insert_data("tcp_package",
                           f"source_port, dest_port, ttl, sequence, acknowledgement," +
                           f"fl_ack, fl_fin, fl_syn, fl_psh, fl_urg, fl_rst, data, date_, time_",
                           (values[0], values[1], values[2], values[3], values[4], values[5], values[6],
                            values[7], values[8], values[9], values[10], values[11],
                            datetime.today(), datetime.now().time()))

    def insert_udp(self, values):
        self.__insert_data("udp_package",
                           f"source_port, dest_port, size, data,date_, time_",
                           (values[0], values[1], values[2], values[3],
                            datetime.today(), datetime.now().time()))

    def insert_icmp(self, values):
        self.__insert_data("icmp_package",
                           "type_icmp, code, checksum, data, date_, time_",
                           (values[0], values[1], values[2], values[3],
                            datetime.today(), datetime.now().time()))

    def insert_other(self, data):
        self.__insert_data("other_package",
                           "data, date_, time_",
                           (data, datetime.today(), datetime.now().time()))

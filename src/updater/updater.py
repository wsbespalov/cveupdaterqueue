import re
import pika
import json
import redis
import urllib
import string
from datetime import datetime
from time import time

import cpe as cpe_module

SETTINGS = dict(
    cache=dict(
        host='localhost',
        port=6379,
        db=3
    ),
    storage=dict(
        host='localhost',
        port=6379,
        db=4
    ),
    queues=dict(
        updater="updater_queue",
    ),
    collections=dict(
        separator="::",
        index="index",
        vulners="vulners"
    ),
    pika=dict(
        host="127.0.0.1",
        port=5672,
        no_ack=True
    )
)

##############################################################################

class UpdateIndexEngine(object):

    def __init__(self, settings={}):
        self.settings = settings
        self.cache_settings = settings.get("cache", {})
        self.cache_host = self.cache_settings.get("host", "localhost")
        self.cache_port = self.cache_settings.get("port", 6379)
        self.cache_db = self.cache_settings.get("db", 3)
        self.cache = redis.StrictRedis(
            host=self.cache_host,
            port=self.cache_port,
            db=self.cache_db
        )
        pass

    @staticmethod
    def serialize_as_json(element):
        try:
            return json.dumps(element)
        except:
            return None

    @staticmethod
    def deserialize_as_json(element):
        try:
            return json.loads(element)
        except:
            return None

    def create_collection_name_by_component_and_version(self, component, version):
        """
        Combine collection name like:
            collection+separator+component+separator+version
            etc.
            index::tomcat::8.0
        If version is empty - use "*".
        If version is None - use "*".
        :param component:
        :param version:
        :return:
        """
        if version is None:
            version = "*"
        if version == "":
            version = "*"
        collection_name = "".join([
            self.settings["collections"]["index"],
            self.settings["collections"]["separator"],
            component,
            self.settings["collections"]["separator"],
            str(version)
        ])
        return collection_name

    def check_if_item_already_in_index_by_component_and_version(self, component, version):
        """
        Get component and version and check if such element already in cache.
        :param component:
        :param version:
        :return:
        """
        collection_name = self.create_collection_name_by_component_and_version(component, version)
        try:
            result_of_search = self.cache.llen(collection_name)
            if result_of_search == 0:
                return False
            return True
        except:
            return None

    def get_all_elements_from_cache_as_list_by_collection_name(self, collection_name):
        """
        Get all elements as list from cache by collection name.
        All elements will be deserialize in JSON.
        :param collection_name:
        :return:
        """
        try:
            elements_in_cache = self.cache.lrange(
                collection_name, 0, -1
            )
        except:
            elements_in_cache = list()
        list_of_components = list()
        for element in elements_in_cache:
            list_of_components.append(
                self.deserialize_as_json(
                    element
                )
            )
        return list_of_components

    def save_list_of_elements_into_cache(self, collection_name, list_to_save=[]):
        """
        Push all elements in list into cache.
        All elements will be serialize in JSON.
        :param collection_name:
        :param list_to_save:
        :return:
        """
        for element in list_to_save:
            try:
                self.cache.rpush(
                    collection_name,
                    self.serialize_as_json(
                        element
                    )
                )
            except:
                pass

    def clear_collection(self, collection_name):
        """
        Just clear collection in cache.
        :param collection_name:
        :return:
        """
        try:
            self.cache.delete(
                collection_name
            )
            return True
        except:
            return False

    def correct_version(self, version, unquote=True, only_digits_and_dot_in_version=True):
        """
        Correct version value:
        1. If version is None - return "*".
        2. If version is empty - return "*".
        3. If "unquote" - make unquoted.
        4. If "only_digits_and_dot_in_version" - make it.
        :param version:
        :return:
        """
        new_version_value = version
        if version is None:
            return "*"
        if version == "":
            return "*"
        if unquote:
            try:
                new_version_value = urllib.parse.unquote(new_version_value)
            except:
                pass
        if only_digits_and_dot_in_version:
            allow = string.digits + '.' + '(' + ')'
            new_version_value = re.sub('[^%s]' % allow, '', new_version_value)
        return new_version_value

    def correct_component(self, component, unquote=True):
        new_component_value = component
        if unquote:
            try:
                new_component_value = urllib.parse.unquote(new_component_value)
            except:
                pass
        return new_component_value

    @staticmethod
    def extract_component_and_version_from_cpe_string(cpe_string):
        result = None
        try:
            cpep = cpe_module.CPE(cpe_string, cpe_module.CPE.VERSION_2_2)
        except:
            try:
                cpep = cpe_module.CPE(cpe_string, cpe_module.CPE.VERSION_2_3)
            except:
                try:
                    cpep = cpe_module.CPE(cpe_string, cpe_module.CPE.VERSION_UNDEFINED)
                except:
                    cpep = None
        if cpep is not None:
            c22_product = cpep.get_product() if cpep is not None else []
            c22_version = cpep.get_version() if cpep is not None else []
            result = dict()
            result["component"] = c22_product[0] if isinstance(c22_product, list) and len(c22_product) > 0 else None
            result["version"] = c22_version[0] if isinstance(c22_version, list) and len(c22_version) > 0 else None
        if result["component"] is None or result["version"] is None:
            result = None
        if result["component"] == "" or result["version"] == "":
            result = None
        return result

    def append_item_in_index(self, item_to_update):
        component = item_to_update["component"]
        version = item_to_update["version"]
        collection_name = self.create_collection_name_by_component_and_version(
            component=component,
            version=version
        )
        items_in_cache = self.get_all_elements_from_cache_as_list_by_collection_name(
            collection_name=collection_name
        )
        items_to_save = list()
        if len(items_in_cache) == 0:
            # This is the first element in collection
            items_to_save.append(
                item_to_update
            )
        else:
            # There are some elements in collection - update one
            # if its ID is the same
            for one_item in items_in_cache:
                element = one_item.copy()
                if element["id"] == item_to_update["id"]:
                    element.update(item_to_update)
                items_to_save.append(
                    element
                )
                del element
        self.save_list_of_elements_into_cache(
            collection_name=collection_name,
            list_to_save=items_to_save
        )

    def update_items_in_cache_index(self, items_to_update):
        count = 0
        for one_item in items_to_update:
            one_item_in_json = json.loads(one_item)
            cpe_strings = one_item_in_json["cpe"]["data"]
            for one_cpe_string in cpe_strings:
                component_and_version = self.extract_component_and_version_from_cpe_string(
                    one_cpe_string
                )
                if component_and_version is not None:
                    component = self.correct_component(component_and_version["component"])
                    version = self.correct_version(component_and_version["version"])
                    one_item_in_json["component"] = component
                    one_item_in_json["version"] = version
                    self.append_item_in_index(one_item_in_json)
                    count += 1



##############################################################################

updater_engine = UpdateIndexEngine(SETTINGS)

##############################################################################

updater_queue_name = SETTINGS["queues"]["updater"]

updater_connection = pika.BlockingConnection(
    pika.ConnectionParameters(
        host=SETTINGS["pika"]["host"],
        port=SETTINGS["pika"]["port"],
        credentials = pika.PlainCredentials('guest', 'guest')
    )
)

updater_channel = updater_connection.channel()
updater_channel.queue_declare(queue=updater_queue_name)

def updater_callback(ch, method, properties, body):
    mybody = json.loads(body)
    print("Receive payload: {}".format(mybody))
    items_to_update = list()
    items_to_update.append(mybody)
    updater_engine.update_items_in_cache_index(items_to_update)

updater_channel.basic_consume(
    updater_callback,
    queue=updater_queue_name,
    no_ack=bool(SETTINGS["pika"]["no_ack"])
)

print("Start Updater listener...")

updater_channel.start_consuming()

##############################################################################
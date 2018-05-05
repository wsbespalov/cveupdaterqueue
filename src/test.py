import pika
import json
import time
from datetime import datetime
import urllib.request as req
import zipfile
from io import BytesIO
import gzip
import bz2
from datetime import datetime
from dateutil.parser import parse as parse_datetime

class CVEItem(object):

    def __init__(self, data):
        """
        Parse JSON data structure for ONE item
        :param data: (dict) - Item to parse
        """
        cve = data.get("cve", {})

        # Get Data Type -> str
        self.data_type = cve.get("data_type", None)
        # Get Data Format -> str
        self.data_format = cve.get("data_format", None)
        # Get Data Version -> str
        self.data_version = cve.get("data_version", None)  # Data version like 4.0
        # Get CVE ID like CVE-2002-2446 -> str
        CVE_data_meta = cve.get("CVE_data_meta", {})
        self.id = CVE_data_meta.get("ID", None)
        # Get Vendor -> JSON with list -> {"data": vendor_data}
        affects = cve.get("affects", {})
        vendor = affects.get("vendor", {})
        vendor_data = []
        vdata = vendor.get("vendor_data", [])
        for vd in vdata:
            vendor_name = vd.get("vendor_name", None)  # vendor name - one value - VENDOR
            product = vd.get("product", {})
            product_data = product.get("product_data", [])
            for pd in product_data:
                product_name = pd.get("product_name", None)  # product name - list of products for VENDOR
                version = pd.get("version", {})
                version_data = version.get("version_data", [])
                for vd in version_data:
                    version_value = vd.get("version_value", None)  # version value list of versions for PRODUCT
                    # create json set
                    if version_value is not None and product_name is not None and vendor_name is not None:
                        jtemplate = dict(
                            vendor=vendor_name,
                            product=product_name,
                            version=version_value
                        )
                        vendor_data.append(jtemplate)
                        del jtemplate
        self.vendor = {"data": vendor_data}
        # GET CWEs -> JSON with list -> {"data": cwe}
        cwe = []
        problemtype = cve.get("problemtype", {})
        problemtype_data = problemtype.get("problemtype_data", [])
        for pd in problemtype_data:
            description = pd.get("description", [])
            for d in description:
                value = d.get("value", None)
                if value is not None:
                    cwe.append(value)
        self.cwe = {"data": cwe}
        # GET RREFERENCES -> JSON with list -> {"data": references}
        references = []
        ref = cve.get("references", {})
        reference_data = ref.get("reference_data", [])
        for rd in reference_data:
            url = rd.get("url", None)
            if url is not None:
                references.append(url)
        self.references = {"data": references}
        # GET DESCRIPTION -> str
        self.description = ""
        descr = cve.get("description", {})
        description_data = descr.get("description_data", [])
        for dd in description_data:
            value = dd.get("value", "")
            self.description = self.description + value
        # GET cpe -> JSON with list -> {"data": cpe22}
        cpe22 = []
        conf = data.get("configurations", {})
        nodes = conf.get("nodes", [])
        for n in nodes:
            cpe = n.get("cpe", [])
            for c in cpe:
                c22 = c.get("cpe22Uri", None)
                cpe22.append(c22)
        self.cpe = {"data": cpe22}

        impact = data.get("impact", {})

        # GET CVSSV2
        self.cvssv2 = {}
        baseMetricV2 = impact.get("baseMetricV2", {})
        cvssV2 = baseMetricV2.get("cvssV2", {})
        self.cvssv2["version"] = cvssV2.get("version", "")
        self.cvssv2["vectorString"] = cvssV2.get("vectorString", "")
        self.cvssv2["accessVector"] = cvssV2.get("accessVector", "")
        self.cvssv2["accessComplexity"] = cvssV2.get("accessComplexity", "")
        self.cvssv2["authentication"] = cvssV2.get("authentication", "")
        self.cvssv2["confidentialityImpact"] = cvssV2.get("confidentialityImpact", "")
        self.cvssv2["integrityImpact"] = cvssV2.get("integrityImpact", "")
        self.cvssv2["availabilityImpact"] = cvssV2.get("availabilityImpact", "")
        self.cvssv2["baseScore"] = cvssV2.get("baseScore", "")
        self.cvssv2["severity"] = baseMetricV2.get("severity", "")
        self.cvssv2["exploitabilityScore"] = baseMetricV2.get("exploitabilityScore", "")
        self.cvssv2["impactScore"] = baseMetricV2.get("impactScore", "")
        self.cvssv2["obtainAllPrivilege"] = baseMetricV2.get("obtainAllPrivilege", "")
        self.cvssv2["obtainUserPrivilege"] = baseMetricV2.get("obtainUserPrivilege", "")
        self.cvssv2["obtainOtherPrivilege"] = baseMetricV2.get("obtainOtherPrivilege", "")
        self.cvssv2["userInteractionRequired"] = baseMetricV2.get("userInteractionRequired", "")

        # GET CVSSV3
        self.cvssv3 = {}
        baseMetricV3 = impact.get("baseMetricV3", {})
        cvssV3 = baseMetricV3.get("cvssV3", {})
        self.cvssv3["version"] = cvssV3.get("version", "")
        self.cvssv3["vectorString"] = cvssV3.get("vectorString", "")
        self.cvssv3["attackVector"] = cvssV3.get("attackVector", "")
        self.cvssv3["attackComplexity"] = cvssV3.get("attackComplexity", "")
        self.cvssv3["privilegesRequired"] = cvssV3.get("privilegesRequired", "")
        self.cvssv3["userInteraction"] = cvssV3.get("userInteraction", "")
        self.cvssv3["scope"] = cvssV3.get("scope", "")
        self.cvssv3["confidentialityImpact"] = cvssV3.get("confidentialityImpact", "")
        self.cvssv3["integrityImpact"] = cvssV3.get("integrityImpact", "")
        self.cvssv3["availabilityImpact"] = cvssV3.get("availabilityImpact", "")
        self.cvssv3["baseScore"] = cvssV3.get("baseScore", "")
        self.cvssv3["baseSeverity"] = cvssV3.get("baseSeverity", "")
        self.cvssv3["exploitabilityScore"] = baseMetricV3.get("exploitabilityScore", "")
        self.cvssv3["impactScore"] = baseMetricV3.get("impactScore", "")

        # GET Dates

        self.publishedDate = data.get("publishedDate", datetime.utcnow())
        self.lastModifiedDate = data.get("lastModifiedDate", datetime.utcnow())

        # Additional fields
        self.component = ""
        self.version = ""

    def to_json(self):
        return json.dumps(self,
                          default=lambda o: o.__dict__,
                          sort_keys=True)


def download_cve_file(source):
    file_stream, response_info = get_file(source)
    try:
        result = json.load(file_stream)
        if "CVE_Items" in result:
            return result["CVE_Items"], response_info
        return None
    except json.JSONDecodeError as json_error:
        print('Get an JSON decode error: {}'.format(json_error))
        return None


def parse_cve_file(items=None):
    if items is None:
        items = []
    parsed_items = []
    for item in items:
        parsed_items.append(CVEItem(item).to_json())
    return parsed_items


def unify_time(dt):
    if isinstance(dt, str):
        if 'Z' in dt:
            dt = dt.replace('Z', '')
        return parse_datetime(dt)

    if isinstance(dt, datetime):
        return parse_datetime(str(dt))


def unify_bool(param):
    if isinstance(param, bool):
        if param is False:
            return 'false'
        elif param is True:
            return 'true'
    elif isinstance(param, str):
        if param == 'False':
            return 'false'
        elif param == 'True':
            return 'true'
        elif param == '':
            return 'false'
    elif isinstance(param, type(None)):
        return 'false'

def get_file(getfile, unpack=True, raw=False, HTTP_PROXY=None):
    try:
        if HTTP_PROXY:
            proxy = req.ProxyHandler({'http': HTTP_PROXY, 'https': HTTP_PROXY})
            auth = req.HTTPBasicAuthHandler()
            opener = req.build_opener(proxy, auth, req.HTTPHandler)
            req.install_opener(opener)

        data = response = req.urlopen(getfile)

        if raw:
            return data

        if unpack:
            if 'gzip' in response.info().get('Content-Type'):
                buf = BytesIO(response.read())
                data = gzip.GzipFile(fileobj=buf)
            elif 'bzip2' in response.info().get('Content-Type'):
                data = BytesIO(bz2.decompress(response.read()))
            elif 'zip' in response.info().get('Content-Type'):
                fzip = zipfile.ZipFile(BytesIO(response.read()), 'r')
                length_of_namelist = len(fzip.namelist())
                if length_of_namelist > 0:
                    data = BytesIO(fzip.read(fzip.namelist()[0]))
        return data, response
    except Exception as ex:
        return None, str(ex)

SETTINGS = dict(
    sources = dict(
        cve_modified="https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz",
        cve_recent="https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.gz",
        cve_base="https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-",
        cve_base_postfix=".json.gz",
        cpe22="https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.2.xml.zip",
        cpe23="https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip",
        cwe="http://cwe.mitre.org/data/xml/cwec_v2.8.xml.zip",
        capec="http://capec.mitre.org/data/xml/capec_v2.6.xml",
        ms="http://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx",
        d2sec="http://www.d2sec.com/exploits/elliot.xml",
        npm="https://api.nodesecurity.io/advisories",
    ),
    cache_for_indexer = dict(
        host="localhost",
        port=6379,
        db=3
    ),
    start_year=2018,

)


queue_name_updater = "updater_queue"

connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))

channel = connection.channel()

channel.queue_declare(queue=queue_name_updater)

# Populate
current_year = datetime.now().year
for year in range(SETTINGS["start_year"], current_year + 1):
    start_time = time.time()
    source = SETTINGS["sources"]["cve_base"] + str(year) + SETTINGS["sources"]["cve_base_postfix"]
    cve_item, response = download_cve_file(source)

    parsed_cve_item = parse_cve_file(cve_item)

    count = len(parsed_cve_item)

    print("Populate {} elements in CVE-{} takes {} sec.".format(count, year, time.time() - start_time))

    for element in parsed_cve_item:
        body = json.dumps(element)
        channel.basic_publish(exchange='', routing_key=queue_name_updater, body=body)

# Modified

modified_items, response = download_cve_file(SETTINGS["sources"]["cve_modified"])
modified_parsed = parse_cve_file(modified_items)

print("Get {} modified elements from source".format(len(modified_parsed)))

for element in modified_parsed:
    body = json.dumps(element)
    channel.basic_publish(exchange='', routing_key=queue_name_updater, body=body)


# Recent

recent_items, response = download_cve_file(SETTINGS["sources"]["cve_recent"])
recent_parsed = parse_cve_file(recent_items)

print("Get {} recent elements from source".format(len(recent_parsed)))

for element in recent_parsed:
    body = json.dumps(element)
    channel.basic_publish(exchange='', routing_key=queue_name_updater, body=body)



connection.close()
print("Complete all.")
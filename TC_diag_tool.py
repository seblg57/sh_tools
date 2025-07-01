import os
import re
import xml.etree.ElementTree as ET
import subprocess
import platform
import psycopg2
import requests
import getpass

class colors:
    RESET = '\033[0m'
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def option_1():
    texte = "=== Option 1: Threatconnect Configuration ==="
    largeur_cadre = 120
    texte_centre = texte.center(largeur_cadre)
    print("*" * 120)
    print()
    print(texte_centre)
    print()
    print("*" * 120)
    init_script_path = '/etc/init.d/threatconnect'

    with open(init_script_path, 'r') as file:
        init_script_content = file.read()
    tcuser_password = getpass.getpass("Enter Postgres tcuser password: ")
    basedir_match = re.search(r'^BASEDIR=(.*)$', init_script_content, re.MULTILINE)

    if basedir_match:
        basedir = basedir_match.group(1).strip('"')  # Remove any surrounding quotes
        file_path = f'{basedir}/config/threatconnect.xml'
        print(f'XML Config : {colors.GREEN}{file_path.ljust(40)}{colors.RESET}')
        print("-" * 120)
    else:
        print('BASEDIR not found.')
        print("-" * 120)
        return

    if basedir_match:
        basedir = basedir_match.group(1).strip('"')  # Remove any surrounding quotes

        try:
            disk_usage = os.statvfs(basedir)
            total_space_gb = (disk_usage.f_frsize * disk_usage.f_blocks) / (1024 ** 3)
            du_output = subprocess.check_output(['du', '-sh', basedir]).decode('utf-8')
            used_space = du_output.split('\t')[0]

            print("-" * 120)
            print(f"Free storage for '{basedir}': {total_space_gb:.2f} GB".ljust(40))
            print(f"Storage used by '{basedir}': {used_space:<10}")
            print("-" * 120)

        except Exception as e:
            print(f"Error while calculating disk space: {e}")

    else:
        print("BASEDIR not found in the init script.")

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        namespaces = {'ns': 'urn:jboss:domain:15.0'}
        with open(file_path, 'r') as xml_file:
            xml_content = xml_file.read()
        host_match = re.search(r'<connection-url>jdbc:postgresql://([^/:]+):5432', xml_content)
        if host_match:
            postgresql_host = host_match.group(1)
            print("{:<40}: {}".format("PostgreSQL Host", postgresql_host))
        else:
            print("{:<40}: {}".format("PostgreSQL host not found in the XML", ""))

        version_file_path = f'{basedir}/config/version.txt'
        if os.path.isfile(version_file_path):
            with open(version_file_path, 'r') as version_file:
                version_content = version_file.read().strip()
            print("{:<40}: {}".format("Threatconnect Version", version_content))

        try:
            with open("/etc/os-release") as f:
                 for line in f:
                     if line.startswith("PRETTY_NAME="):
                       distro = line.strip().split("=")[1].strip('"')
                       break
                 else:
                     distro = "Unknown"
        except Exception:
            distro = "Unknown"

        print("{:<40}: {}".format("Linux Distribution", distro))


        apps_message_broker_enabled_elem = root.find(".//ns:property[@name='appsMessageBrokerEnabled']", namespaces)
        monitors_enabled_elem = root.find(".//ns:property[@name='monitorsEnabled']", namespaces)
        tc_app_services_enabled_elem = root.find(".//ns:property[@name='tc.appServicesEnabled']", namespaces)
        tc_saml2_enabled_elem = root.find(".//ns:property[@name='tc.saml2.enabled']", namespaces)
        remote_destination_host_elem = root.find(".//ns:property[@name='remote-destination host']", namespaces)
        property_db_type_elem = root.find(".//ns:property[@name='property.db.type']", namespaces)
        tc_pb_server_worker_size_elem = root.find(".//ns:property[@name='tc.pbServerWorkerSize']", namespaces)
        queue_batchjobmdb_maxsession_elem = root.find(".//ns:property[@name='property.queue.batchjobmdb.maxsession']", namespaces)
        queue_hostmonitormdb_maxsession_elem = root.find(".//ns:property[@name='property.queue.hostmonitormdb.maxsession']", namespaces)
        queue_inboundmailmdb_maxsession_elem = root.find(".//ns:property[@name='property.queue.inboundmailmdb.maxsession']", namespaces)
        queue_jobexecutionmdb_maxsession_elem = root.find(".//ns:property[@name='property.queue.jobexecutionmdb.maxsession']", namespaces)
        queue_joblogrequestmdb_maxsession_elem = root.find(".//ns:property[@name='property.queue.joblogrequestmdb.maxsession']", namespaces)
        private_pb_server_elem = root.find(".//ns:property[@name='tc.privatePbServer']", namespaces)
        apps_message_broker_enabled = apps_message_broker_enabled_elem.attrib.get('value') if apps_message_broker_enabled_elem is not None else None
        monitors_enabled = monitors_enabled_elem.attrib.get('value') if monitors_enabled_elem is not None else None
        tc_app_services_enabled = tc_app_services_enabled_elem.attrib.get('value') if tc_app_services_enabled_elem is not None else None
        tc_saml2_enabled = tc_saml2_enabled_elem.attrib.get('value') if tc_saml2_enabled_elem is not None else None
        property_db_type = property_db_type_elem.attrib.get('value') if property_db_type_elem is not None else None
        tc_pb_server_worker_size = tc_pb_server_worker_size_elem.attrib.get('value') if tc_pb_server_worker_size_elem is not None else None
        #queue_batchjobmdb_maxsession = queue_batchjobmdb_maxsession_elem.attrib.get('value') if queue_batchjobmdb_maxsession_elem is not None else None
        #queue_hostmonitormdb_maxsession = queue_hostmonitormdb_maxsession_elem.attrib.get('value') if queue_hostmonitormdb_maxsession_elem is not None else None
        #queue_inboundmailmdb_maxsession = queue_inboundmailmdb_maxsession_elem.attrib.get('value') if queue_inboundmailmdb_maxsession_elem is not None else None
        #queue_jobexecutionmdb_maxsession = queue_jobexecutionmdb_maxsession_elem.attrib.get( 'value') if queue_jobexecutionmdb_maxsession_elem is not None else None
        #queue_joblogrequestmdb_maxsession = queue_joblogrequestmdb_maxsession_elem.attrib.get('value') if queue_joblogrequestmdb_maxsession_elem is not None else None
        private_pb_server = private_pb_server_elem.attrib.get('value') if private_pb_server_elem is not None else None
        remote_destinations = root.findall(".//ns:remote-destination", namespaces)
        texte2 = "=== Wildfly Configuration ==="
        largeur_cadre = 120
        texte2_centre = texte2.center(largeur_cadre)
        print("*" * 120)
        print(texte2_centre)
        print("*" * 120)
        print("{:<43}: {}".format("appsMessageBrokerEnabled", apps_message_broker_enabled))
        print("{:<43}: {}".format("monitorsEnabled", monitors_enabled))
        print("{:<43}: {}".format("tc.appServicesEnabled", tc_app_services_enabled))
        print("{:<43}: {}".format("tc.saml2.enabled", tc_saml2_enabled))
        print("{:<43}: {}".format("property.db.type", property_db_type))
        print("{:<43}: {}".format("tc.pbServerWorkerSize", tc_pb_server_worker_size))
        #print("{:<40}: {}".format("queue.batchjobmdb.maxsession", queue_batchjobmdb_maxsession))
        #print("{:<40}: {}".format("queue.hostmonitormdb.maxsession", queue_hostmonitormdb_maxsession))
        #print("{:<40}: {}".format("queue.inboundmailmdb.maxsession", queue_inboundmailmdb_maxsession))
        #print("{:<40}: {}".format("queue.jobexecutionmdb.maxsession", queue_jobexecutionmdb_maxsession))
        #print("{:<40}: {}".format("queue.joblogrequestmdb.maxsession", queue_joblogrequestmdb_maxsession))
        print("{:<43}: {}".format("tc.privatePbServer", private_pb_server))
        remote_destinations = root.findall(".//ns:remote-destination", namespaces)
        dest_names = ["remote-messaging", "mail-smtp"]
        for i, dest in enumerate(remote_destinations):
            host_value = dest.get('host')
            if host_value and i < len(dest_names):
                host_value_after_equal = host_value.split("host=")[-1]
                print("{:<43}: {}".format(dest_names[i], host_value_after_equal))
    except Exception as e:
        print(f'Error: {e}')

    try:
        conn = psycopg2.connect(
            dbname="threatconnect",
            user="tcuser",
            password=tcuser_password,
            host=postgresql_host,
            port="5432"
        )

        names = [
            'appCatalogServerURL',
            'appsApiUrl',
            'systemUrl',
            'searchUrl',
            'appsPythonHome',
            'documentStorageLocalPath',
            'loggingLocation',
            'playbooksLoggingLocation',
            'appsJavaHome',
            'appExecutionDBDaysToKeep',
            'playbookForkPoolSize',
            'tqlQueryTimeout',
            'appMessageBrokerMaxConnections',
            'appMessageBrokerHost'
        ]

        sql_query = "SELECT value FROM systemconfig WHERE name = %s"

        try:
            texte3 = "=== TC UI Configuration ==="
            largeur_cadre = 120
            texte3_centre = texte3.center(largeur_cadre)
            print("*" * 120)
            print(texte3_centre)
            print("*" * 120)

            cursor = conn.cursor()
            for name in names:
                cursor.execute(sql_query, (name,))
                row = cursor.fetchone()
                value = row[0] if row else "Not found"

                print("{:<40}: {}".format(name, value))
        except Exception as e:
            print(f"Error while executing SQL query: {e}")
        finally:

            cursor.close()
            conn.close()


    except Exception as e:
        print(f"Error while connecting to the database: {e}")
    print()
    input("Press any key to return to the menu...")
    os.system('cls' if os.name == 'nt' else 'clear')

######################################################################
#Opensearch modular requests
def get_opensearch_cluster_info(search_url):
    try:
        cluster_status_response = requests.get(f"{search_url}/_cluster/health?pretty")
        cluster_status = cluster_status_response.json()
        return cluster_status
    except Exception as e:
        print(f"Error while fetching Elasticsearch info: {e}")
        return None

def option_2():
    texte = "=== Option 1: OpenSearch Cluster Informations ==="
    largeur_cadre = 120
    texte_centre = texte.center(largeur_cadre)
    print("*" * 120)
    print(texte_centre)
    print("*" * 120)

    init_script_path = '/etc/init.d/threatconnect'

    with open(init_script_path, 'r') as file:
        init_script_content = file.read()
        tcuser_password = getpass.getpass("Enter Postgres tcuser password: ")

    basedir_match = re.search(r'^BASEDIR=(.*)$', init_script_content, re.MULTILINE)

    if basedir_match:
        basedir = basedir_match.group(1).strip('"')  # Remove any surrounding quotes
        file_path = f'{basedir}/config/threatconnect.xml'
        print(f'XML Config : {file_path}')
        print("-" * 120)
    else:
        print('BASEDIR not found.')
        print("-" * 120)
        return

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        namespaces = {'ns': 'urn:jboss:domain:15.0'}
        with open(file_path, 'r') as xml_file:
            xml_content = xml_file.read()
        host_match = re.search(r'<connection-url>jdbc:postgresql://([a-zA-Z0-9\.\-\[\]:]+)', xml_content)
        if host_match:
            postgresql_host = host_match.group(1)
            print("{:<40}: {}".format("PostgreSQL Host", postgresql_host))
        else:
            print("{:<40}: {}".format("PostgreSQL host not found in the XML", ""))

        try:
            conn = psycopg2.connect(
                dbname="threatconnect",
                user="tcuser",
                password=tcuser_password,
                host=postgresql_host,
                port="5432"
            )
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM systemconfig WHERE name = 'searchUrl'")
            search_url = cursor.fetchone()[0]
            cursor.close()
            conn.close()

            print("{:<40}: {}".format("Opensearch URL", search_url))  # Print search URL here

            cluster_status = get_opensearch_cluster_info(search_url)
            if cluster_status:
                print("=" * 120)
                print("{:<40}: {:<80}".format("Cluster Name", cluster_status['cluster_name']))
                # Print other cluster status details
                print("=" * 120)
            else:
                print("Failed to retrieve cluster health information.")

        except Exception as e:
            print(f"Error while connecting to the database: {e}")

    except Exception as e:
        print(f"Error: {e}")

    print()
    input("Press any key to return to the menu...")
    os.system('cls' if os.name == 'nt' else 'clear')


def option_3():
    import re
    import certifi
    texte6 = "=== Option 3: SSL Certificates Control ==="
    largeur_cadre = 120
    texte6_centre = texte6.center(largeur_cadre)
    print("*" * 120)
    print()
    print(texte6_centre)
    print()
    print("*" * 120)
    init_script_path = '/etc/init.d/threatconnect'

    with open(init_script_path, 'r') as file:
        init_script_content = file.read()

    basedir_match = re.search(r'^BASEDIR=(.*)$', init_script_content, re.MULTILINE)

    if basedir_match:
        basedir = basedir_match.group(1).strip('"')  # Remove any surrounding quotes
        keystore_path = f'{basedir}/config/keystore.jks'
        print(f'XML Config : {colors.GREEN}{keystore_path.ljust(40)}{colors.RESET}')
        print("-" * 120)
    else:
        print('BASEDIR not found.')
        print("-" * 120)
        return
    if basedir_match:
        basedir = basedir_match.group(1).strip('"')  # Remove any surrounding quotes
        file_path = f'{basedir}/config/threatconnect.xml'
    tree = ET.parse(file_path)
    root = tree.getroot()
    namespaces = {'ns': 'urn:jboss:domain:15.0'}
    with open(file_path, 'r') as xml_file:
        xml_content = xml_file.read()
    host_match = re.search(r'<connection-url>jdbc:postgresql://([^/:]+):5432', xml_content)
    if host_match:
        postgresql_host = host_match.group(1)
        print("{:<40}: {}".format("PostgreSQL Host", postgresql_host))
    else:
        print("{:<40}: {}".format("PostgreSQL host not found in the XML", ""))
    # Prompt for the keystore password
    keystore_password = getpass.getpass("Enter keystore password: ")
    tcuser_password = getpass.getpass("Enter Postgres tcuser password: ")

    texte77 = " SSL signed or self signed verification "
    largeur_cadre = 120
    texte77_centre = texte77.center(largeur_cadre)
    print("-" * 120)
    print(texte77_centre)
    print("-" * 120)
    def verify_certificate(certificate_details):
        """
        Verify if the certificate is self-signed or signed by another authority
        """
        issuer = certificate_details.get('Issuer')
        subject = certificate_details.get('Subject')

        if issuer == subject:
            return f"{colors.RED}Self-signed{colors.RESET}"
        else:
            return f"{colors.GREEN}Signed by another authority{colors.RESET}"

    try:
        keytool_output = subprocess.check_output(
            ['keytool', '-list', '-v', '-keystore', keystore_path, '-storepass', keystore_password],
            universal_newlines=True
        )

        def is_root_cert_present(root_cert):
            with open(certifi.where(), 'rb') as file:
                certifi_data = file.read()
            return root_cert in certifi_data

        def load_root_cert_from_file(cert_file):
            try:
                with open(cert_file, 'rb') as file:
                    return file.read()
            except FileNotFoundError:
                print("File not found.")
                return None

        root_cert_file = input("Please provide the path to the root certificate file, or press Enter to skip: ")

        if root_cert_file.strip():
            root_cert_data = load_root_cert_from_file(root_cert_file)
            if root_cert_data:
                if is_root_cert_present(root_cert_data):
                    print(f"{colors.GREEN}Root certificate is present in the Python certificate trust store.{colors.RESET}")
                    print("-" * 120)
                else:
                    print(f"{colors.RED}Root certificate is not present in the Python certificate trust store.{colors.RESET}")
                    print("-" * 120)
            else:
                print("Skipping root certificate verification.")
                print("-" * 120)

        certificates = []
        current_cert = {}
        for line in keytool_output.split('\n'):
            if line.startswith('Alias name:'):
                if current_cert:
                    if current_cert.get('Alias') == 'tc':
                        certificates.insert(0, current_cert)  # Insert the 'tc' certificate at the beginning
                    else:
                        certificates.append(current_cert)
                current_cert = {'Alias': line.split(':')[1].strip()}
            elif line.startswith('Owner:'):
                current_cert['Owner'] = line.split(':')[1].strip()
            elif line.startswith('Valid from:'):
                current_cert['Validity'] = line.split(':')[1].strip()
            elif line.startswith('SubjectAlternativeName') and current_cert.get('Alias') == 'tc':
                san_parts = line.split(':')
                if len(san_parts) > 1:
                    current_cert['SAN'] = san_parts[1].strip()
        for cert in certificates:
            verification_result = verify_certificate(cert)
            print(f"Certificate {cert['Alias']} verification result: {verification_result}")


        # Print the extracted certificate information
        texte7 = "=== Certificats used in Threatconnect Keystore ==="
        largeur_cadre = 120
        texte7_centre = texte7.center(largeur_cadre)
        print("*" * 120)
        print(texte7_centre)
        print("*" * 120)
        print("{:<20} {:<70} {:<40}".format('Alias', 'Owner', 'Validity'))
        print("=" * 120)
        for cert in certificates:
            owner = cert.get('Owner', '')
            validity = cert.get('Validity', '')
            if len(owner) > 70:
                owner = owner[:67] + '...'
            if len(validity) > 40:
                validity = validity[:37] + '...'
            print("{:<20} {:<70} {:<40}".format(cert.get('Alias', ''), owner, validity))
            if cert.get('Alias') == 'tc' and 'SAN' in cert:
                print("Subject Alternative Name:", cert['SAN'])
            print("-" * 120)
    except subprocess.CalledProcessError as e:
        print("Error:", e.output)

    try:
        conn = psycopg2.connect(
            dbname="threatconnect",
            user="tcuser",
            password=tcuser_password,
            host=postgresql_host,
            port="5432"
        )

        names = [
            'systemUrl',
            'secureSystemUrl',
            'appMessageBrokerHost'
        ]

        sql_query = "SELECT value FROM systemconfig WHERE name = %s"
        sql_query_java="SELECT value FROM systemconfig WHERE name = 'appsJavaHome'"
        def extract_alphanumeric_with_dot(input_str):
            # Supprimer les parties indésirables de la valeur
            input_str = input_str.replace("http://", "")
            input_str = input_str.replace(":62000", "")
            return re.sub(r'[^a-zA-Z0-9.]', '', input_str)

        try:
            texte8 = "=== Checking that CN correspond to the TC UI values ==="
            largeur_cadre = 120
            texte8_centre = texte8.center(largeur_cadre)
            print("*" * 120)
            print(texte8_centre)
            print("=" * 120)
            cursor = conn.cursor()
            cursor.execute(sql_query_java)
            row = cursor.fetchone()
            appsJavaHome_value = row[0] if row else "Not found"
            for name in names:
                if name not in ['systemUrl', 'appMessageBrokerHost', 'secureSystemUrl']:
                    continue
                cursor.execute(sql_query, (name,))
                row = cursor.fetchone()
                value = row[0] if row else "Not found"

                if name == 'systemUrl':
                    for cert in certificates:
                        if cert.get('Alias') == 'tc' and 'Owner' in cert:
                            cn_from_cert = extract_alphanumeric_with_dot(
                                cert['Owner'].split(',')[0][3:])
                            if cn_from_cert in value:
                                print("{:<20}: {}{}{}".format(name, colors.GREEN, value, colors.RESET))
                            else:
                                print("{:<20}: {}".format(name, value))
                elif name == 'secureSystemUrl':
                    if 'https://' in value:
                        print("{:<20}: {}".format(name, value))
                    else:
                        print("{:<20}: {}{}{}".format(name, colors.RED, value, colors.RESET))
                elif name == 'appMessageBrokerHost':
                    print("{:<20}: {}".format(name, value))

            keytool_cacert_output = subprocess.check_output(
                ['keytool', '-list', '-v', '-keystore', f'{appsJavaHome_value}/lib/security/cacerts', '-storepass', 'changeit'],
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            tc_alias_present = False
            for line in keytool_cacert_output.split('\n'):
                if line.startswith('Alias name: tc'):
                    tc_alias_present = True
                    break

            if tc_alias_present:
                print("-" * 120)
                print(f"{colors.GREEN}tc alias is present in the cacerts keystore.{colors.RESET}")
                print("-" * 120)
            else:
                print("-" * 120)
                print(f"{colors.RED}Threatconnect certificate is not present in the cacerts keystore. Use SSL toolbox to import it{colors.RESET}")
                print("-" * 120)

        except Exception as e:
            print(f"Error occurred: {e}")

        finally:
            cursor.close()
            conn.close()


    except Exception as e:
        print(f"Error while displaying: {e}")
        return
    print()
    input("Press any key to return to the menu...")
    os.system('cls' if os.name == 'nt' else 'clear')


def option_4():
    texte44 = "=== Option 4: Postgres Server Configuration ==="
    largeur_cadre = 120
    texte44_centre = texte44.center(largeur_cadre)
    print("*" * 120)
    print()
    print(texte44_centre)
    print()
    print("*" * 120)
    init_script_path = '/etc/init.d/threatconnect'

    with open(init_script_path, 'r') as file:
        init_script_content = file.read()

    basedir_match = re.search(r'^BASEDIR=(.*)$', init_script_content, re.MULTILINE)

    if basedir_match:
        basedir = basedir_match.group(1).strip('"')  # Remove any surrounding quotes
        file_path = f'{basedir}/config/threatconnect.xml'
        print(f'XML Config : {colors.GREEN}{file_path.ljust(40)}{colors.RESET}')
        print("-" * 120)
    else:
        print('BASEDIR not found.')
        print("-" * 120)
        return

    if basedir_match:
        basedir = basedir_match.group(1).strip('"')  # Remove any surrounding quotes
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        namespaces = {'ns': 'urn:jboss:domain:15.0'}
        with open(file_path, 'r') as xml_file:
            xml_content = xml_file.read()
        host_match = re.search(r'<connection-url>jdbc:postgresql://([^/:]+):5432', xml_content)
        if host_match:
            postgresql_host = host_match.group(1)
            print("{:<40}: {}".format("PostgreSQL Host", postgresql_host))
            print()
        else:
            print("{:<40}: {}".format("PostgreSQL host not found in the XML", ""))
            print()
        postgres_user_password = getpass.getpass("Enter Postgres admin password: ")
        conn = psycopg2.connect(
            dbname="threatconnect",
            user="postgres",
            password=postgres_user_password,
            host=postgresql_host,
            port="5432"
        )
        names = [
            'max_connections',
            'max_worker_processes',
            'shared_buffers',
            'effective_cache_size'
        ]

        sql_query = "SELECT setting FROM pg_settings WHERE name = %s"

        try:
            texte4 = "=== Postgres Configuration ==="
            largeur_cadre = 120
            texte4_centre = texte4.center(largeur_cadre)
            print("*" * 120)
            print(texte4_centre)
            print("*" * 120)
            cursor = conn.cursor()
            for name in names:
                cursor.execute(sql_query, (name,))
                row = cursor.fetchone()
                value = row[0] if row else "Not found"
                print("{:<40}: {}".format(name, value))
        except Exception as e:
            print(f"Error while executing SQL query: {e}")

        try:
            texte4 = "=== Postgres Performances ==="
            largeur_cadre = 120
            texte4_centre = texte4.center(largeur_cadre)
            print("*" * 120)
            print(texte4_centre)
            print("*" * 120)

            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM pg_stat_activity WHERE usename = 'tcuser';")
            row = cursor.fetchone()
            print("{:<40}: {}".format("Active Connections for tcuser", row[0]))

            cursor.execute("SELECT state FROM pg_stat_replication;")
            rows = cursor.fetchall()
            print("{:<40}: {}".format("Replication State", ", ".join([row[0] for row in rows])))

            cursor.execute("SELECT numbackends FROM pg_stat_database WHERE datname = 'threatconnect';")
            row = cursor.fetchone()
            print("{:<40}: {}".format("Number of Backends", row[0]))

            cursor.execute("SELECT tup_inserted FROM pg_stat_database WHERE datname = 'threatconnect';")
            row = cursor.fetchone()
            print("{:<40}: {}".format("Rows Inserted", row[0]))

            cursor.execute("SELECT blks_read  FROM pg_stat_database WHERE datname = 'threatconnect';")
            row = cursor.fetchone()
            print("{:<40}: {}".format("Blocks Read", row[0]))

            cursor.execute("SELECT xact_commit  FROM pg_stat_database WHERE datname = 'threatconnect';")
            row = cursor.fetchone()
            print("{:<40}: {}".format("Transactions Committed", row[0]))

            cursor.execute("SELECT xact_rollback  FROM pg_stat_database WHERE datname = 'threatconnect';")
            row = cursor.fetchone()
            print("{:<40}: {}".format("Transactions Rolled Back", row[0]))

        except Exception as e:
            print(f"Error while executing SQL query: {e}")

        sql_query = "SELECT ROUND(pg_database_size('threatconnect') / (1024.0 * 1024.0 * 1024.0), 2) AS size_in_gb;"

        try:
            texte44 = "=== Threatconnect Database Statistics ==="
            largeur_cadre = 120
            texte44_centre = texte44.center(largeur_cadre)
            print("*" * 120)
            print(texte44_centre)
            print("*" * 120)

            cursor = conn.cursor()

            cursor.execute(sql_query)
            row = cursor.fetchone()
            db_size = row[0] if row else "Not found"

            print("{:<40}: {}".format("Database Size in Gb", db_size))

        except Exception as e:
            print(f"Error while executing SQL query: {e}")

        sql_queries = [
            "SELECT COUNT(*) AS alert_count FROM alert;",
            "SELECT COUNT(*) AS indicator_count FROM indicator;",
            "SELECT COUNT(*) AS indicator_attribute_count FROM indicatorattribute;",
            "SELECT COUNT(*) AS bucket_count FROM bucket;",
            "SELECT COUNT(*) AS bucket_attribute_count FROM bucketattribute;",
            "SELECT COUNT(*) AS common_indicator_count FROM commonindicator;",
            "SELECT COUNT(*) AS tag_count FROM tag;"
        ]

        try:
            cursor = conn.cursor()

            for sql_query in sql_queries:
                cursor.execute(sql_query)
                row = cursor.fetchone()
                table_name = sql_query.split()[5]
                row_count = row[0] if row else "Not found"
                print("{:<40}: {}".format(table_name.capitalize() + " Count", row_count))

        except Exception as e:
            print(f"Error while executing SQL query: {e}")

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error while connecting to the database: {e}")
    # Add your option 2 logic here
    print()
    input("Press any key to return to the menu...")
    os.system('cls' if os.name == 'nt' else 'clear')

def option_5():
    print("Option 3 selected")
    # Add your option 3 logic here


def option_6():
    print("Option 2 selected")
    # Add your option 2 logic here


def option_7():
    print("Option 3 selected")
    # Add your option 3 logic here


def option_8():
    print("Option 3 selected")
    # Add your option 3 logic here


def option_9():
    print("Option 3 selected")


def display_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    texte11 = "=== Threatconnect Check Script ==="
    largeur_cadre = 120
    texte11_centre = texte11.center(largeur_cadre)
    print("*" * 120)
    print()
    print(texte11_centre)
    print()
    print("*" * 120)
    print("[1] Option 1 : Threatconnect Configuration Check")
    print("[2] Option 2 : Opensearch Cluster Check")
    print("[3] Option 3 : SSL Certificats Check")
    print("[4] Option 4 : Postgres Server Check")
    print("[5] Option 5")
    print("[6] Option 6")
    print("[7] Option 7")
    print("[8] Option 8")
    print("[9] Option 9 : Create new keystore with SSL signed certificates")
    print("[10] Exit")
    print("=" * 120)


# Main loop
while True:
    display_menu()
    choice = input("Enter your choice: ")

    if choice == '1':
        os.system('cls' if os.name == 'nt' else 'clear')
        option_1()
    elif choice == '2':
        os.system('cls' if os.name == 'nt' else 'clear')
        option_2()
    elif choice == '3':
        os.system('cls' if os.name == 'nt' else 'clear')
        option_3()
    elif choice == '4':
        os.system('cls' if os.name == 'nt' else 'clear')
        option_4()
    elif choice == '5':
        option_1()
    elif choice == '6':
        option_1()
    elif choice == '7':
        option_1()
    elif choice == '8':
        option_1()
    elif choice == '9':
        option_1()
    elif choice == '10':
        print("Exiting...")
        break
    else:
        print("Invalid choice. Please enter a valid option.")

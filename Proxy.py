# Include the libraries for socket and system calls
import socket
import sys
import os
import argparse
import re

import email.utils
import datetime
from datetime import timezone, datetime


# 1MB buffer size
BUFFER_SIZE = 1000000


# Get the IP address and Port number to use for this web proxy server
parser = argparse.ArgumentParser()
parser.add_argument('hostname', help='the IP Address Of Proxy Server')
parser.add_argument('port', help='the port number of the proxy server')
args = parser.parse_args()
proxyHost = args.hostname
proxyPort = int(args.port)

# Create a server socket, bind it to a port and start listening
try:
  # Create a server socket
  # ~~~~ INSERT CODE ~~~~
  serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  # ~~~~ END CODE INSERT ~~~~
  print ('Created socket')
except:
  print ('Failed to create socket')
  sys.exit()

try:
  # Bind the the server socket to a host and port
  # ~~~~ INSERT CODE ~~~~
  serverSocket.bind((proxyHost, proxyPort)) # bind the socket to server address and port
  # ~~~~ END CODE INSERT ~~~~
  print ('Port is bound')
except:
  print('Port is already in use')
  sys.exit()

try:
  # Listen on the server socket
  # ~~~~ INSERT CODE ~~~~
  serverSocket.listen(1) # listen for incoming connections
  # ~~~~ END CODE INSERT ~~~~
  print ('Listening to socket')
except:
  print ('Failed to listen')
  sys.exit()

# continuously accept connections
while True:
  print ('Waiting for connection...')
  clientSocket = None

  # Accept connection from client and store in the clientSocket
  try:
    # ~~~~ INSERT CODE ~~~~
    clientSocket, addr = serverSocket.accept() # accept connections from outside
    # ~~~~ END CODE INSERT ~~~~
    print ('Received a connection')
  except:
    print ('Failed to accept connection')
    sys.exit()
  
  # Receive message from client and get the data in the buffer size
  # Get HTTP request from client
  # and store it in the variable: message_bytes
  # ~~~~ INSERT CODE ~~~~
  message_bytes = clientSocket.recv(1024) # receive message from client
  # ~~~~ END CODE INSERT ~~~~
  message = message_bytes.decode('utf-8')
  print ('Received request:')
  print ('< ' + message)

  # Extract the method, URI and version of the HTTP client request 
  requestParts = message.split()
  method = requestParts[0]
  URI = requestParts[1]
  version = requestParts[2]

  print ('Method:\t\t' + method)
  print ('URI:\t\t' + URI)
  print ('Version:\t' + version)
  print ('')

  # Get the requested resource from URI
  # Remove http protocol from the URI
  URI = re.sub('^(/?)http(s?)://', '', URI, count=1)

  # Remove parent directory changes - security
  URI = URI.replace('/..', '')

  # Split hostname from resource name
  resourceParts = URI.split('/', 1)
  hostname = resourceParts[0]
  resource = '/'

  if len(resourceParts) == 2:
    # Resource is absolute URI with hostname and resource
    resource = resource + resourceParts[1]

  print ('Requested Resource:\t' + resource)

  # Check if resource is in cache
  try:
    cacheLocation = './' + hostname + resource
    if cacheLocation.endswith('/'):
        cacheLocation = cacheLocation + 'default'

    print ('Cache location:\t\t' + cacheLocation)

    fileExists = os.path.isfile(cacheLocation)
    
    # Check whether the file is currently in the cache
    cacheFile = open(cacheLocation, "r")
    cacheData = cacheFile.readlines()

    print ('Cache hit! Loading from cache file: ' + cacheLocation)
    # ProxyServer finds a cache hit
    # Send back response to client 
    # ~~~~ INSERT CODE ~~~~
    # check if the cache is still valid by checking the status code
    cache_status = cacheData[0].split(' ')[1] 
    if not cacheData or len(cacheData[0].split()) < 2:
      print("Cache file is empty or invalid. Fetching from origin server.")
      raise Exception("Invalid cache data")

    # if cache is moved permanently or redirected, send the client to original server
    cache_valid = True 
    if cache_status == '301' or cache_status == '302':
      print('Cache is moved permanently or redirected')
      # extract the new location from the cache and set the new location
      hostname, resource = cacheLocation.split('=')[1].split('&')[0].split('/')[2]
      resource = '/' 
      cache_valid = False
    else:
      pass 
    
    # extract the cache control header from the cache
    for data in cacheData:
      # calculate the age of the cache
      if 'Date' in data:
        cache_time = data.split(':', 1)[1].strip()
        # Define the expected date format according to RFC 2616
        date_format = "%a, %d %b %Y %H:%M:%S GMT"
        # calculate the age of the cache
        cache_age = (datetime.datetime.now(timezone.utc) - datetime.datetime.strptime(cache_time, date_format).replace(tzinfo=timezone.utc)).total_seconds()
      
      # check if the cache is reusable
      if 'Cache-Control' in data:
        cache_control = data.split(':', 1)[1]
        if cache_control == 'no-cache'or cache_control == 'no-store': #RFC 2616. 14.9.1
          print('Cache is not reusable')
          cache_valid = False
      
      # check if the cache is still valid
      if 'max_age' in data and int(data.split(',')[1].split('=')[1]) <= cache_age:
        print('Cache is expired')
        cache_valid = False
      
      if cache_valid == False:
        open('OSError', 'r')
      # use connection socket to send the cache data to the client
      else:
        for item in cacheData:
          clientSocket.send(item)
          exit()
    # ~~~~ END CODE INSERT ~~~~
    cacheFile.close()
    print ('Sent to the client:')
    print ('> ' + ' '.join(cacheData))
  
  except OSError:
    # cache miss.  Get resource from origin server
    originServerSocket = None
    # Create a socket to connect to origin server
    # and store in originServerSocket
    # ~~~~ INSERT CODE ~~~~
    originServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ~~~~ END CODE INSERT ~~~~

    print ('Connecting to:\t\t' + hostname + '\n')
    try:
      # Get the IP address for a hostname
      address = socket.gethostbyname(hostname)
      # Connect to the origin server
      # ~~~~ INSERT CODE ~~~~
      originServerSocket.connect((address, 80))
      # ~~~~ END CODE INSERT ~~~~
      print ('Connected to origin Server')

      originServerRequest = ''
      originServerRequestHeader = ''
      # Create origin server request line and headers to send
      # and store in originServerRequestHeader and originServerRequest
      # originServerRequest is the first line in the request and
      # originServerRequestHeader is the second line in the request
      # ~~~~ INSERT CODE ~~~~
      originServerRequestLine = method + ' ' + resource + ' ' + version
      originServerRequestHeader = 'Host: ' + hostname + '\r\n'
      # ~~~~ END CODE INSERT ~~~~

      # Construct the request to send to the origin server
      request = originServerRequestLine + '\r\n' + originServerRequestHeader + '\r\n\r\n'

      # Request the web resource from origin server
      print ('Forwarding request to origin server:')
      for line in request.split('\r\n'):
        print ('> ' + line)

      try:
        originServerSocket.sendall(request.encode()) 
      except socket.error:
        print ('Forward request to origin failed')
        sys.exit()

      print('Request sent to origin server\n')

      # Get the response from the origin server
      # ~~~~ INSERT CODE ~~~~
      response = ''
      #receive the response from the origin server if not in cache
      response = originServerSocket.recv(1024) 

      # validate the response from the origin server
      cached_response = True 

      response_parts = response.split('\r\n')
      response_status = response_parts[0]

      # check the response status code
      if response_status == '200':
        print('retrieve the response from the origin server')
      elif response_status == '301':
        print ('URL moved permanently')
      elif response_status == '302':
        print('URL moved temporarily')
      elif response_status == '404':
        cached_response = False
        print('URL not found')
      # ~~~~ END CODE INSERT ~~~~

      # Send the response to the client
      # ~~~~ INSERT CODE ~~~~
      clientSocket.send(response)
      # ~~~~ END CODE INSERT ~~~~

      if cached_response == True:
      # Create a new file in the cache for the requested file.
        cacheDir, file = os.path.split(cacheLocation)
        print ('cached directory ' + cacheDir)
        if not os.path.exists(cacheDir):
          os.makedirs(cacheDir)
        cacheFile = open(cacheLocation, 'wb')

      # Save origin server response in the cache file
      # ~~~~ INSERT CODE ~~~~
      for lines in response:
        cacheFile.write(lines) # write the entire response to the cache file
      # ~~~~ END CODE INSERT ~~~~
      cacheFile.close()
      print ('cache file closed')

      # finished communicating with origin server - shutdown socket writes

      print ('origin response received. Closing sockets')
      originServerSocket.shutdown(socket.SHUT_WR)
      
      clientSocket.shutdown(socket.SHUT_WR)
      print ('client socket shutdown for writing')
    except OSError as err:
      print ('origin server request failed. ' + err.strerror)

  try:
    clientSocket.close()
  except:
    print ('Failed to close client socket')



Joseph Lee
CS4480
4/26/2014

PA3 - SSL Encryption

HOW TO:

Bob's Server:
	To Run: extract bob.tar. From the bob folder run the server.py file by typing 	
		"python27 server.py"
	
	Options: Options available are -IP (to specify IP address:port) or -V to enable all 
		 print statements. 
		
		 -IP Option: This option is not necessary, by default the server will
		             determine the IP address of the machine and bind it to that
			     IP at port 12333. However if you want to specify the IP
                             address, include the option "-IP <IP address>:<port>" or
			     "-IP <IP address>" to use default port 12333.

		 -V option:  Used to enable print statements per specs of assignment.

	Example: This should look like the following:
		 "python27 server.py -v"
		 "python27 server.py -ip <ipaddress>"
		 "python27 server.py -ip <ipaddress>:<port> -v"

		 Any combination should work!

Alice's Client:
	To Run: extract alice.tar from the alice folder run client.py file by tying
		"python27 client.py"

	Options: The options for the client are exactly the same as the server.

	Example: "python27 -ip <ipaddress> -v" or any combination like above.
		 
		 Note: For your convenience the server will print the IP address that it   
                 binds to. This should make it easy to bind Alice to the Bob.
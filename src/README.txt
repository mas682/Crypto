

To compile:
1. javac -cp bcprov-jdk15on-160.jar;. *.javac


To run:
1. java -cp bcprov-jdk15on-160.jar;. RunGroupServer
2. repeat for file server and myclientapp
3. upon starting my client app, it will prompt to enter a username twice
It does this to generate a file userKeys which will hold a users public, private, and group server key
for ease of use of the app.  MAKE SURE YOU USE THE SAME USERNAME FOR THIS AND THE GROUP SERVER.  It will 
then go to generate a key pair for the group server and share the public key with the user
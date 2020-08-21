# Digital Signature Algorithm


##1. Messages' file format

All the messages we want to sign are in the same file, with one different message on each line.

##2. Signature Mode

`sign fileName` allows signing all the messages content in `fileName`. The signatures are stored in `output_signatures`

##3. Verification Mode

`verif filename` allows verifying the previous generates signatures. 

##4. Test Mode

`test number` compute `number` signatures and return the computing time.


'''
:Authors:         Shashank Agrawal
:Date:            5/2016
'''

from charm.toolbox.pairinggroup import PairingGroup, GT
from ac17 import AC17CPABE
from datetime import datetime, timedelta

def main():
    totalETime = timedelta(0)
    totalGTime = timedelta(0)
    totalDTime = timedelta(0)

    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')
    
    # AC17 CP-ABE under DLIN (2-linear)
    cpabe = AC17CPABE(pairing_group, 2)

    # Get (data owner's) master key and public key
    (pk, msk) = cpabe.setup()

    # Define attribute universe
    # attr_list = ['ONE', 'TWO', 'THREE', 'age=5']
    attr_list = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '100']
    # Define policy
    # policy_str = '((ONE and THREE) and (TWO or FOUR) and (age==5))'
    policy_str_100 = '1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10 and 11 and 12 and 13 and 14 and 15 and 16 and 17 and 18 and 19 and 20 and 21 and 22 and 23 and 24 and 25 and 26 and 27 and 28 and 29 and 30 and 31 and 32 and 33 and 34 and 35 and 36 and 37 and 38 and 39 and 40 and 41 and 42 and 43 and 44 and 45 and 46 and 47 and 48 and 49 and 50 and 51 and 52 and 53 and 54 and 55 and 56 and 57 and 58 and 59 and 60 and 61 and 62 and 63 and 64 and 65 and 66 and 67 and 68 and 69 and 70 and 71 and 72 and 73 and 74 and 75 and 76 and 77 and 78 and 79 and 80 and 81 and 82 and 83 and 84 and 85 and 86 and 87 and 88 and 89 and 90 and 91 and 92 and 93 and 94 and 95 and 96 and 97 and 98 and 99 and 100'
    policy_str_75 = '1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10 and 11 and 12 and 13 and 14 and 15 and 16 and 17 and 18 and 19 and 20 and 21 and 22 and 23 and 24 and 25 and 26 and 27 and 28 and 29 and 30 and 31 and 32 and 33 and 34 and 35 and 36 and 37 and 38 and 39 and 40 and 41 and 42 and 43 and 44 and 45 and 46 and 47 and 48 and 49 and 50 and 51 and 52 and 53 and 54 and 55 and 56 and 57 and 58 and 59 and 60 and 61 and 62 and 63 and 64 and 65 and 66 and 67 and 68 and 69 and 70 and 71 and 72 and 73 and 74 and 75' 
    policy_str_50 = '1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10 and 11 and 12 and 13 and 14 and 15 and 16 and 17 and 18 and 19 and 20 and 21 and 22 and 23 and 24 and 25 and 26 and 27 and 28 and 29 and 30 and 31 and 32 and 33 and 34 and 35 and 36 and 37 and 38 and 39 and 40 and 41 and 42 and 43 and 44 and 45 and 46 and 47 and 48 and 49 and 50'
    policy_str_25 = '1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10 and 11 and 12 and 13 and 14 and 15 and 16 and 17 and 18 and 19 and 20 and 21 and 22 and 23 and 24 and 25'


    # choose a random message (one element in GT)
    msg = pairing_group.random(GT)
    
    # encrypt ciphertext using key and policy
    startTime = datetime.now()
    ctxt = cpabe.encrypt(pk, msg, policy_str_100)
    endTime = datetime.now()
    totalETime = totalETime + (endTime - startTime)

    # Generate secret key for decryption based on list of attributes of data user
    startTime = datetime.now()
    key = cpabe.keygen(pk, msk, attr_list)
    endTime = datetime.now()
    totalGTime = totalGTime + (endTime - startTime)

    # decryption
    startTime = datetime.now()
    rec_msg = cpabe.decrypt(pk, ctxt, key)
    endTime = datetime.now()
    totalDTime = totalDTime + (endTime - startTime)

    print("Avg encryption time: {0}".format(str(totalETime)))
    print("Avg keygen time: {0}".format(str(totalGTime)))
    print("Avg decryption time: {0}".format(str(totalDTime)))
    
    if debug:
        if rec_msg == msg:
            print ("Successful decryption.")
        else:
            print ("Decryption failed.")


if __name__ == "__main__":
    debug = True
    main()
{-# LANGUAGE OverloadedStrings #-}

module Blockchain.ECIES (
  decryptECIES,
  encryptECIES,
  ECIESMessage(..)
  ) where

import Crypto.Cipher.AES
import Crypto.Hash.SHA256
import Crypto.PubKey.ECC.DH
import Crypto.Types.PubKey.ECC
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import Data.HMAC

import Blockchain.ExtWord
-- import Debug.Trace

theCurve::Curve
theCurve = getCurveByName SEC_p256k1

intToBytes::Integer->[Word8]
intToBytes x = map (fromIntegral . (x `shiftR`)) [256-8, 256-16..0]

ctr::[Word8]
ctr=[0,0,0,1]

s1::[Word8]
s1 = []


data ECIESMessage =
  ECIESMessage {
    eciesForm::Word8, --See ansi x9.62 section 4.3.6 (I currently only handle form=4)
    eciesPubKey::Point,
    eciesCipherIV::B.ByteString,
    eciesCipher::B.ByteString,
    eciesMac::[Word8]
    } deriving (Show)

instance Binary ECIESMessage where
  get = do
    bs <- getRemainingLazyByteString
    let bsStrict = BL.toStrict $ bs
        theLength  =  B.length $ bsStrict
        form = errorHead "bsStrict is null" $ 
               B.unpack $ bsStrict
        pubKeyX =  toInteger . bytesToWord256 . B.unpack $ B.take 32 $ B.drop 1 $ bsStrict
        pubKeyY =  toInteger . bytesToWord256 . B.unpack $ B.take 32 $ B.drop 33 $ bsStrict
        cipherIV = B.take 16 $ B.drop 65 $ bsStrict
        cipher = B.take (theLength - 113) $ B.drop 81 $ bsStrict
        mac = B.unpack $ B.take 32 $ B.drop (theLength-32) bsStrict
    -- form <- getWord8
    -- pubKeyX <- fmap (toInteger . bytesToWord256 . B.unpack) $ getByteString 32
    -- pubKeyY <- fmap (toInteger . bytesToWord256 . B.unpack) $ getByteString 32
    -- cipherIV <- getByteString 16
    -- cipher <- getByteString (length - (113))  
    -- mac <- sequence $ replicate 32 getWord8
    return $ ECIESMessage form (Point pubKeyX pubKeyY) cipherIV cipher mac

  put (ECIESMessage form (Point pubKeyX pubKeyY) cipherIV cipher mac) = do
    putWord8 form
    putByteString (B.pack . word256ToBytes . fromInteger $ pubKeyX)
    putByteString (B.pack . word256ToBytes . fromInteger $ pubKeyY)
    putByteString cipherIV
    putByteString cipher
    sequence_ $ map putWord8 mac
  put x = error $ "unsupported case in call to put for ECIESMessage: " ++ show x

errorHead::String->[a]->a
errorHead _ (x:_) = x
errorHead msg _ = error msg


encrypt::B.ByteString->B.ByteString->B.ByteString->B.ByteString
encrypt key cipherIV input = encryptCTR (initAES key) cipherIV input 

encryptECIES::PrivateNumber->PublicPoint->B.ByteString->B.ByteString->ECIESMessage
encryptECIES myPrvKey otherPubKey cipherIV msg =
  ECIESMessage {
    eciesForm = 4, --form=4 indicates pubkey is not compressed
    eciesPubKey=calculatePublic theCurve myPrvKey,
    eciesCipherIV=cipherIV,
    eciesCipher=cipher,
    eciesMac= --trace ("################### mkey: " ++ show mKey) $
      --trace ("################### cipherWithIV: " ++ show cipherWithIV) $
        hmac (HashMethod (B.unpack . hash . B.pack) 512) (B.unpack mKey) (B.unpack cipherWithIV)
    }
  where
    SharedKey sharedKey = --trace ("##################### sharedKey: " ++ show (getShared theCurve myPrvKey otherPubKey)) $
                          getShared theCurve myPrvKey otherPubKey
    key = hash $ B.pack (ctr ++ intToBytes sharedKey ++ s1)
    eKey = B.take 16 key
    mKeyMaterial = -- trace ("##################### sharedKey: " ++ show (B.take 16 $ B.drop 16 key)) $
                   (B.take 16 $ B.drop 16 key)
    mKey = hash mKeyMaterial
    cipher = encrypt eKey cipherIV msg
    cipherWithIV = cipherIV `B.append` cipher

decryptECIES::PrivateNumber->ECIESMessage->B.ByteString
decryptECIES myPrvKey msg =
  decryptCTR (initAES eKey) (eciesCipherIV msg) (eciesCipher msg)
  where
    SharedKey sharedKey = getShared theCurve myPrvKey (eciesPubKey msg)
    key = hash $ B.pack (ctr ++ intToBytes sharedKey ++ s1)
    eKey = B.take 16 key

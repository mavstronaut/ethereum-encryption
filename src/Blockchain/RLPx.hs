{-# LANGUAGE OverloadedStrings #-}

module Blockchain.RLPx (
  ethCryptConnect,
  ethCryptAccept
  ) where

import Control.Exception
import Control.Monad
import Control.Monad.IO.Class
import Crypto.Cipher.AES
import qualified Crypto.Hash.SHA3 as SHA3
import Crypto.PubKey.ECC.DH
import Crypto.Random
import Crypto.Types.PubKey.ECC
import Data.Binary
import Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import Data.Conduit
import qualified Data.Conduit.Binary as CB
import Data.Maybe
import qualified Network.Haskoin.Internals as H

import qualified Blockchain.AESCTR as AES
import Blockchain.ECIES
import Blockchain.Error
import Blockchain.EthEncryptionException
import Blockchain.ExtendedECDSA
import Blockchain.ExtWord
import Blockchain.Frame
import Blockchain.Handshake






--import Debug.Trace

theCurve::Curve
theCurve = getCurveByName SEC_p256k1

intToBytes::Integer->[Word8]
intToBytes x = map (fromIntegral . (x `shiftR`)) [256-8, 256-16..0]

bXor::B.ByteString->B.ByteString->B.ByteString
bXor x y | B.length x == B.length y = B.pack $ B.zipWith xor x y
bXor _ _ = error' "bXor called with two ByteStrings of different length"

ethCryptConnect::MonadIO m=>PrivateNumber->PublicPoint->ConduitM B.ByteString B.ByteString m (EthCryptState, EthCryptState)
ethCryptConnect myPriv otherPubKey = do
  --h <- liftIO $ connectTo ipAddress (PortNumber thePort)

--  liftIO $ putStrLn $ "connected over tcp"
  
  let myNonce = B.pack $ word256ToBytes 20 --TODO- Important!  Don't hardcode this

  handshakeInitBytes <- liftIO $ getHandshakeBytes myPriv otherPubKey myNonce
      
  yield handshakeInitBytes

  handshakeReplyBytes <- fmap BL.toStrict $ CB.take 210
  let replyECIESMsg = decode $ BL.fromStrict handshakeReplyBytes

  when (B.length handshakeReplyBytes /= 210) $ liftIO $ throwIO $ HandshakeException "handshake reply didn't contain enough bytes"
  
  let ackMsg = bytesToAckMsg $ B.unpack $ decryptECIES myPriv replyECIESMsg

--  liftIO $ putStrLn $ "ackMsg: " ++ show ackMsg
------------------------------

  let m_originated=False -- hardcoded for now, I can only connect as client
      
      otherNonce=B.pack $ word256ToBytes $ ackNonce ackMsg

      SharedKey shared' = getShared theCurve myPriv (ackEphemeralPubKey ackMsg)
      shared = B.pack $ intToBytes shared'

      frameDecKey = myNonce `add` otherNonce `add` shared `add` shared
      macEncKey = frameDecKey `add` shared

      ingressCipher = if m_originated then handshakeInitBytes else handshakeReplyBytes
      egressCipher = if m_originated then handshakeReplyBytes else handshakeInitBytes

  -- liftIO $ putStrLn $ "myNonce `add` otherNonce: " ++ show (myNonce `add` otherNonce)
  -- liftIO $ putStrLn $ "myNonce `add` otherNonce `add` shared: " ++ show (myNonce `add` otherNonce `add` shared)
  
  -- liftIO $ putStrLn $ "otherNonce: " ++ show otherNonce

  -- liftIO $ putStrLn $ "frameDecKey: " ++ show frameDecKey

  -- liftIO $ putStrLn $ "shared: " ++ show shared'

  -- liftIO $ putStrLn $ "ingressCipher: " ++ show ingressCipher
  -- liftIO $ putStrLn $ "egressCipher: " ++ show egressCipher

  -- liftIO $ putStrLn $ "macEncKey: " ++ show macEncKey


  return (
          EthCryptState { --encrypt
                          aesState = AES.AESCTRState (initAES frameDecKey) (aesIV_ $ B.replicate 16 0) 0,
                          mac=SHA3.update (SHA3.init 256) $ (macEncKey `bXor` otherNonce) `B.append` egressCipher,
                          key=macEncKey
          },
          EthCryptState { --decrypt
                          aesState = AES.AESCTRState (initAES frameDecKey) (aesIV_ $ B.replicate 16 0) 0,
                          mac=SHA3.update (SHA3.init 256) $ (macEncKey `bXor` myNonce) `B.append` ingressCipher,
                          key=macEncKey
          }
         )

add::B.ByteString->B.ByteString->B.ByteString
add acc val | B.length acc ==32 && B.length val == 32 = SHA3.hash 256 $ val `B.append` acc
add _ _ = error "add called with ByteString of length not 32"

hPubKeyToPubKey::H.PubKey->Point
hPubKeyToPubKey pubKey =
  Point (fromIntegral x) (fromIntegral y)
  where
    x = fromMaybe (error "getX failed in prvKey2Address") $ H.getX hPoint
    y = fromMaybe (error "getY failed in prvKey2Address") $ H.getY hPoint
    hPoint = H.pubKeyPoint pubKey



ethCryptAccept::MonadIO m=>PrivateNumber->Point->ConduitM B.ByteString B.ByteString m (EthCryptState, EthCryptState)
ethCryptAccept myPriv otherPoint = do
--tcpHandshakeServer :: PrivateNumber-> Point-> ConduitM B.ByteString B.ByteString IO EthCryptStateLite
--tcpHandshakeServer prv otherPoint = go
    hsBytes <- CB.take 307

    let eciesMsgIncoming = (decode $ hsBytes :: ECIESMessage)

    when (eciesForm eciesMsgIncoming `elem` [2,3]) $ error "peer connected with unsupported handshake packet"
    
    when (not $ eciesForm eciesMsgIncoming `elem` [2,3,4]) $ error "peer seems to be using EIP 8"
    
    liftIO $ putStrLn $ "++++++++++++++++++ " ++ show (eciesForm eciesMsgIncoming)
        
    let eciesMsgIBytes = (decryptECIES myPriv eciesMsgIncoming )
        iv = B.replicate 16 0

    let SharedKey sharedKey = getShared theCurve myPriv otherPoint
        otherNonce = B.take 32 $ B.drop 161 $ eciesMsgIBytes
        msg = fromIntegral sharedKey `xor` (bytesToWord256 $ B.unpack otherNonce)
        r = bytesToWord256 $ B.unpack $ B.take 32 $ eciesMsgIBytes
        s = bytesToWord256 $ B.unpack $ B.take 32 $ B.drop 32 $ eciesMsgIBytes
        v = head . B.unpack $ B.take 1 $ B.drop 64 eciesMsgIBytes
        yIsOdd = v == 1

        extSig = ExtendedSignature (H.Signature (fromIntegral r) (fromIntegral s)) yIsOdd
        otherEphemeral = hPubKeyToPubKey $
                            fromMaybe (error "malformed signature in tcpHandshakeServer") $
                            getPubKeyFromSignature extSig msg


    entropyPool <- liftIO createEntropyPool
    let g = cprgCreate entropyPool :: SystemRNG
        (myPriv', _) = generatePrivate g $ getCurveByName SEC_p256k1
        myEphemeral = calculatePublic theCurve myPriv'
        myNonce = 25 :: Word256
        ackMsg = AckMessage { ackEphemeralPubKey=myEphemeral, ackNonce=myNonce, ackKnownPeer=False }
        eciesMsgOutgoing = encryptECIES myPriv' otherPoint iv ( BL.toStrict $ encode $ ackMsg )
        eciesMsgOBytes = BL.toStrict $ encode eciesMsgOutgoing

    yield $ eciesMsgOBytes

    let SharedKey ephemeralSharedSecret = getShared theCurve myPriv' otherEphemeral
        ephemeralSharedSecretBytes = intToBytes ephemeralSharedSecret

        myNonceBS = B.pack $ word256ToBytes myNonce
        frameDecKey = otherNonce `add`
                        myNonceBS `add`
                        (B.pack ephemeralSharedSecretBytes) `add`
                        (B.pack ephemeralSharedSecretBytes)
        macEncKey = frameDecKey `add` (B.pack ephemeralSharedSecretBytes)

    {-
    let cState =
          EthCryptStateLite {
            encryptState = AES.AESCTRState (initAES frameDecKey) (aesIV_ $ B.replicate 16 0) 0,
            decryptState = AES.AESCTRState (initAES frameDecKey) (aesIV_ $ B.replicate 16 0) 0,
            egressMAC=
            egressKey=macEncKey,
            ingressMAC=
            ingressKey=macEncKey,
            peerId = calculatePublic theCurve prv,
            isClient = False,
            afterHello = False
          }

    return cState
    -}

    return (
      EthCryptState { --encrypt
         aesState = AES.AESCTRState (initAES frameDecKey) (aesIV_ $ B.replicate 16 0) 0,
         mac=SHA3.update (SHA3.init 256) $ (macEncKey `bXor` otherNonce) `B.append` eciesMsgOBytes,
         key=macEncKey
         },
      EthCryptState { --decrypt
        aesState = AES.AESCTRState (initAES frameDecKey) (aesIV_ $ B.replicate 16 0) 0,
        mac=SHA3.update (SHA3.init 256) $ (macEncKey `bXor` myNonceBS) `B.append` (BL.toStrict hsBytes),
        key=macEncKey
        }
      )





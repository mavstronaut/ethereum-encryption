{-# LANGUAGE OverloadedStrings #-}

module Blockchain.RLPx (
  ethCryptConnect
  ) where

import Control.Monad
import Control.Monad.IO.Class
import Control.Monad.Trans.State
import Crypto.Cipher.AES
import qualified Crypto.Hash.SHA3 as SHA3
import Crypto.PubKey.ECC.DH
import Crypto.Types.PubKey.ECC
import Data.Binary
import Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import Data.Conduit
import qualified Data.Conduit.Binary as CB
import Network
import System.IO
    
import Blockchain.ExtWord

import qualified Blockchain.AESCTR as AES
import Blockchain.Frame
import Blockchain.Handshake

--import Debug.Trace

theCurve::Curve
theCurve = getCurveByName SEC_p256k1

intToBytes::Integer->[Word8]
intToBytes x = map (fromIntegral . (x `shiftR`)) [256-8, 256-16..0]

bXor::B.ByteString->B.ByteString->B.ByteString
bXor x y | B.length x == B.length y = B.pack $ B.zipWith xor x y
bXor _ _ = error "bXor called with two ByteStrings of different length"

ethCryptConnect::MonadIO m=>PrivateNumber->PublicPoint->ConduitM B.ByteString B.ByteString m (EthCryptState, EthCryptState)
ethCryptConnect myPriv otherPubKey = do
  --h <- liftIO $ connectTo ipAddress (PortNumber thePort)

--  liftIO $ putStrLn $ "connected over tcp"
  
  let myNonce = B.pack $ word256ToBytes 20 --TODO- Important!  Don't hardcode this

  handshakeInitBytes <- liftIO $ getHandshakeBytes myPriv otherPubKey myNonce
      
  yield handshakeInitBytes

  handshakeReplyBytes <- fmap BL.toStrict $ CB.take 210
  let replyECEISMsg = decode $ BL.fromStrict handshakeReplyBytes

  when (B.length handshakeReplyBytes /= 210) $ error "handshake reply didn't contain enough bytes"
  
  let ackMsg = bytesToAckMsg $ B.unpack $ decryptECEIS myPriv replyECEISMsg

--  liftIO $ putStrLn $ "ackMsg: " ++ show ackMsg
------------------------------

  let m_originated=False -- hardcoded for now, I can only connect as client
      add::B.ByteString->B.ByteString->B.ByteString
      add acc val | B.length acc ==32 && B.length val == 32 = SHA3.hash 256 $ val `B.append` acc
      add _ _ = error "add called with ByteString of length not 32"

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


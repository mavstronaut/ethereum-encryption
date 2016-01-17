{-# LANGUAGE OverloadedStrings #-}

module Blockchain.UDP (
  getServerPubKey,
  findNeighbors,
  ndPacketToRLP,
  NodeDiscoveryPacket(..),
  Endpoint(..)
  ) where

import Network.Socket
import qualified Network.Socket.ByteString as B

import Control.Exception
import Control.Monad
import qualified Crypto.Hash.SHA3 as SHA3
import Crypto.Types.PubKey.ECC
import Data.Binary
import qualified Data.ByteString as B
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BC
import Data.Maybe
import Data.Time.Clock.POSIX
import qualified Network.Haskoin.Internals as H
import System.Timeout

import Blockchain.Data.RLP
import Blockchain.ExtendedECDSA
import Blockchain.ExtWord
import Blockchain.Format
import Blockchain.SHA

--import Debug.Trace

--I need to use two definitions of PubKey (internally they represent the same thing)
--The one in the Haskoin package allows me to recover signatures.
--The one in the crypto packages let me do AES encryption.
--At some point I have to convert from one PubKey to the other, this function
--lets me to that.
hPubKeyToPubKey::H.PubKey->Point
hPubKeyToPubKey pubKey =
  Point (fromIntegral x) (fromIntegral y)
  where
    x = fromMaybe (error "getX failed in prvKey2Address") $ H.getX hPoint
    y = fromMaybe (error "getY failed in prvKey2Address") $ H.getY hPoint
    hPoint = H.pubKeyPoint pubKey

encrypt::H.PrvKey->Word256->H.SecretT IO ExtendedSignature
encrypt prvKey' theHash = do
  extSignMsg theHash prvKey'

data RawNodeDiscoveryPacket =
  RawNDPacket SHA ExtendedSignature Integer RLPObject deriving (Show)

data NodeDiscoveryPacket =
  Ping Integer Endpoint Endpoint Integer |
  Pong Endpoint Integer Integer |
  FindNode NodeID Integer |
  Neighbors [Neighbor] Integer deriving (Show,Read,Eq)

data Endpoint = Endpoint String Word16 Word16 deriving (Show,Read,Eq)
data Neighbor = Neighbor Endpoint NodeID deriving (Show,Read,Eq)


{-
rlpToNDPacket::Word8->RLPObject->NodeDiscoveryPacket
rlpToNDPacket 0x1 (RLPArray [protocolVersion, RLPArray [ ipFrom, udpPortFrom, tcpPortFrom], RLPArray [ipTo, udpPortTo, tcpPortTo], expiration]) =
    Ping (rlpDecode protocolVersion) (Endpoint (rlpDecode ipFrom) (fromInteger $ rlpDecode udpPortFrom) (fromInteger $ rlpDecode tcpPortFrom))
                                     (Endpoint (rlpDecode ipTo) (fromInteger $ rlpDecode udpPortTo) (fromInteger $ rlpDecode tcpPortTo))
                                     (rlpDecode expiration)
rlpToNDPacket 0x2 (RLPArray [ RLPArray [ ipFrom, udpPortFrom, tcpPortFrom ], replyToken, expiration]) = Pong (Endpoint (rlpDecode ipFrom)
                                                                       (fromInteger $ rlpDecode udpPortFrom)
                                                                       (fromInteger $ rlpDecode tcpPortFrom))
                                                                       (rlpDecode replyToken)
                                                                       (rlpDecode expiration)
--rlpToNDPacket 0x3 (RLPArray [target, expiration]) = FindNode (rlpDecode target) (fromInteger $ rlpDecode expiration)
--rlpToNDPacket 0x4 (RLPArray [ip, port, id', expiration]) = Neighbors (rlpDecode ip) (fromInteger $ rlpDecode port) (rlpDecode id') (rlpDecode expiration)
rlpToNDPacket v x = error $ "Missing case in rlpToNDPacket: " ++ show v ++ ", " ++ show x
-}

ndPacketToRLP::NodeDiscoveryPacket->(Word8, RLPObject)
ndPacketToRLP (Ping ver (Endpoint ipFrom udpPortFrom tcpPortFrom) (Endpoint ipTo udpPortTo tcpPortTo) expiration) =
  (1, RLPArray [rlpEncode ver,
                RLPArray [
                rlpEncode ipFrom,
                rlpEncode $ toInteger udpPortFrom,
                rlpEncode $ toInteger tcpPortFrom],
                RLPArray [
                rlpEncode ipTo,
                rlpEncode $ toInteger udpPortTo,
                rlpEncode $ toInteger tcpPortTo],
                rlpEncode expiration])
ndPacketToRLP (Pong (Endpoint ipFrom udpPortFrom tcpPortFrom) tok expiration) = (2, RLPArray [RLPArray [ rlpEncode ipFrom,
                                                                                                         rlpEncode $ toInteger udpPortFrom,
                                                                                                         rlpEncode $ toInteger tcpPortFrom],
                                                                                                         rlpEncode tok,
                                                                                                         rlpEncode expiration])

ndPacketToRLP (FindNode target expiration) = (3, RLPArray [rlpEncode target, rlpEncode expiration])

--ndPacketToRLP (Neighbors ip port id' expiration) = (4, RLPArray [rlpEncode ip, rlpEncode $ toInteger port, rlpEncode id', rlpEncode expiration])

ndPacketToRLP x = error $ "Unsupported case in call to ndPacketToRLP: " ++ show x






--showPoint::H.Point->String
--showPoint (H.Point x y) = "Point 0x" ++ showHex x "" ++ " 0x" ++ showHex y ""


{-
showPubKey::H.PubKey->String
showPubKey (H.PubKey point) =
  "Point 0x" ++ showHex x "" ++ " 0x" ++ showHex y ""
  where
    x = fromMaybe (error "getX failed in prvKey2Address") $ H.getX point
    y = fromMaybe (error "getY failed in prvKey2Address") $ H.getY point
  
showPubKey (H.PubKeyU _) = error "Missing case in showPubKey: PubKeyU"
-}  



processDataStream'::[Word8]->IO H.PubKey
processDataStream'
  (h1:h2:h3:h4:h5:h6:h7:h8:h9:h10:h11:h12:h13:h14:h15:h16:
   h17:h18:h19:h20:h21:h22:h23:h24:h25:h26:h27:h28:h29:h30:h31:h32:
   r1:r2:r3:r4:r5:r6:r7:r8:r9:r10:r11:r12:r13:r14:r15:r16:
   r17:r18:r19:r20:r21:r22:r23:r24:r25:r26:r27:r28:r29:r30:r31:r32:
   s1:s2:s3:s4:s5:s6:s7:s8:s9:s10:s11:s12:s13:s14:s15:s16:
   s17:s18:s19:s20:s21:s22:s23:s24:s25:s26:s27:s28:s29:s30:s31:s32:
   v:
   theType:rest) = do
  let theHash = bytesToWord256 [h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,
                                h17,h18,h19,h20,h21,h22,h23,h24,h25,h26,h27,h28,h29,h30,h31,h32]
      r = bytesToWord256 [r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r13,r14,r15,r16,
                          r17,r18,r19,r20,r21,r22,r23,r24,r25,r26,r27,r28,r29,r30,r31,r32]
      s = bytesToWord256 [s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12,s13,s14,s15,s16,
                          s17,s18,s19,s20,s21,s22,s23,s24,s25,s26,s27,s28,s29,s30,s31,s32]
      yIsOdd = v == 1 -- 0x1c
      signature = ExtendedSignature (H.Signature (fromIntegral r) (fromIntegral s)) yIsOdd
    
  let (rlp, _) = rlpSplit $ B.pack rest

  let SHA messageHash = hash $ B.pack $ [theType] ++ B.unpack (rlpSerialize rlp)
      publicKey = getPubKeyFromSignature signature messageHash  
      SHA theHash' = hash $ B.pack $ word256ToBytes (fromIntegral r) ++ word256ToBytes (fromIntegral s) ++ [v] ++ [theType] ++ B.unpack (rlpSerialize rlp)
                  
  putStrLn $ "##### theType: " ++ show theType
  putStrLn $ "##### rest: " ++ show rest
  putStrLn $ "##### theHash: " ++ show theHash
  putStrLn $ "##### messageHash: " ++ show messageHash
  putStrLn $ "##### signature: " ++ show signature

  when (theHash /= theHash') $ error "bad UDP data sent from peer, the hash isn't correct"
                  
  return $ fromMaybe (error "malformed signature in call to processDataStream") $ publicKey

processDataStream' _ = error "processDataStream' called with too few bytes"

newtype NodeID = NodeID B.ByteString deriving (Show, Read, Eq)

instance RLPSerializable NodeID where
  rlpEncode (NodeID x) = RLPString x
  rlpDecode (RLPString x) = NodeID x
  rlpDecode x = error $ "unsupported rlp in rlpDecode for NodeID: " ++ show x

instance Format NodeID where
  format (NodeID x) = BC.unpack $ B16.encode x

data UDPException = UDPTimeout deriving (Show)

instance Exception UDPException where
                      
getServerPubKey::H.PrvKey->String->PortNumber->IO (Either SomeException Point)
getServerPubKey myPriv domain port = do
  withSocketsDo $ bracket getSocket close (talk myPriv)
    where
      getSocket = do
        (serveraddr:_) <- getAddrInfo Nothing (Just domain) (Just $ show port)
        s <- socket (addrFamily serveraddr) Datagram defaultProtocol
        _ <- connect s (addrAddress serveraddr)
        return s

      talk::H.PrvKey->Socket->IO (Either SomeException Point)
      talk prvKey' socket' = do
        timestamp <- fmap round getPOSIXTime
        let (theType, theRLP) =
              ndPacketToRLP $
              Ping 4 (Endpoint "127.0.0.1" (fromIntegral $ port) 30303) (Endpoint "127.0.0.1" (fromIntegral $ port) 30303) timestamp
            theData = B.unpack $ rlpSerialize theRLP
            SHA theMsgHash = hash $ B.pack $ (theType:theData)

        ExtendedSignature signature yIsOdd <-
          H.withSource H.devURandom $ encrypt prvKey' theMsgHash

        let v = if yIsOdd then 1 else 0 -- 0x1c else 0x1b
            r = H.sigR signature
            s = H.sigS signature
            theSignature =
              word256ToBytes (fromIntegral r) ++ word256ToBytes (fromIntegral s) ++ [v]
            theHash = B.unpack $ SHA3.hash 256 $ B.pack $ theSignature ++ [theType] ++ theData

        _ <- B.send socket' $ B.pack $ theHash ++ theSignature ++ [theType] ++ theData

        --According to https://groups.google.com/forum/#!topic/haskell-cafe/aqaoEDt7auY, it looks like the only way we can time out UDP recv is to 
        --use the Haskell timeout....  I did try setting socket options also, but that didn't work.
        pubKey <- try (timeout 5000000 (B.recv socket' 2000 >>= processDataStream' . B.unpack)) :: IO (Either SomeException (Maybe H.PubKey))

        case pubKey of
          Right Nothing -> return $ Left $ SomeException UDPTimeout
          Left x -> return $ Left x
          Right (Just x) -> return $ Right $ hPubKeyToPubKey x

findNeighbors::H.PrvKey->String->PortNumber->IO ()
findNeighbors myPriv domain port = do
  withSocketsDo $ bracket getSocket close (talk myPriv)
    where
      getSocket = do
        (serveraddr:_) <- getAddrInfo Nothing (Just domain) (Just $ show port)
        s <- socket (addrFamily serveraddr) Datagram defaultProtocol
        _ <- connect s (addrAddress serveraddr)
        return s

      talk::H.PrvKey->Socket->IO ()
      talk prvKey' socket' = do
        let (theType, theRLP) =
              ndPacketToRLP $
              FindNode (NodeID $ fst $ B16.decode "eab4e595d178422cb8b31eddde2d6dda74ad16609693614a29a214d2b2f457a7c97a442e74e58afd1b16657c5c5908255a450d8a202e8d3b2b31c9b17e7221f3") 100000000000000000
            theData = B.unpack $ rlpSerialize theRLP
            SHA theMsgHash = hash $ B.pack $ (theType:theData)

        ExtendedSignature signature yIsOdd <-
          H.withSource H.devURandom $ encrypt prvKey' theMsgHash

        let v = if yIsOdd then 1 else 0 -- 0x1c else 0x1b
            r = H.sigR signature
            s = H.sigS signature
            theSignature =
              word256ToBytes (fromIntegral r) ++ word256ToBytes (fromIntegral s) ++ [v]
            theHash = B.unpack $ SHA3.hash 256 $ B.pack $ theSignature ++ [theType] ++ theData

        putStrLn "before"
                    
        _ <- B.send socket' $ B.pack $ theHash ++ theSignature ++ [theType] ++ theData

        putStrLn "after"

        pubKey <- B.recv socket' 10 >>= print -- processDataStream' . B.unpack

        print pubKey

        putStrLn "after recv"
        
        --return $ hPubKeyToPubKey pubKey





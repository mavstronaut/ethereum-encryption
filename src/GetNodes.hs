
import Data.Maybe
import Control.Monad.IO.Class
import Crypto.PubKey.ECC.DH
import Crypto.Random
import Crypto.Types.PubKey.ECC
import Network.Haskoin.Internals as H
import System.Environment

import Blockchain.UDP

main = do
  [address] <- getArgs
  
  entropyPool <- liftIO createEntropyPool

  let g = cprgCreate entropyPool :: SystemRNG
      (myPriv, _) = generatePrivate g $ getCurveByName SEC_p256k1
  
  qqqq <- getServerPubKey (fromMaybe (error "invalid private number in main") $ H.makePrvKey $ fromIntegral myPriv) address 30303

  print qqqq

  findNeighbors (fromMaybe (error "invalid private number in main") $ H.makePrvKey $ fromIntegral myPriv) address 30303


module Blockchain.EthEncryptionException (
  EthEncryptionException(..)
  ) where

import Control.Exception.Lifted

data EthEncryptionException =
  HandshakeException String
  | PeerHungUp deriving (Show)

instance Exception EthEncryptionException where

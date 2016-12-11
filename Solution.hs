{-# LANGUAGE OverloadedStrings, NamedFieldPuns, RecordWildCards, ScopedTypeVariables #-}

module Main where

import Data.List
import Network.Pcap
import System.Environment (getArgs)
import Control.Applicative
import Control.Monad hiding (join)
import Control.Arrow (second)
import qualified Data.ByteString as B
import Data.ByteString.Char8 (singleton)
import qualified Data.Attoparsec.ByteString as A
import Data.Attoparsec.Combinator (count)
import Data.Int (Int64)
import Data.IORef
import Data.Maybe (fromMaybe)
import Data.List (find)

import Data.Binary.Get

data Offer = Offer B.ByteString B.ByteString deriving (Show, Eq, Ord)

data QuotePacket = Packet { time      :: B.ByteString
                          , issueCode :: B.ByteString
                          , bids      :: [Offer]
                          , asks      :: [Offer]
                          }
    deriving (Show, Eq, Ord)

type PktTime = Int64
type TimedQuotePkt = (QuotePacket, PktTime)

parseOffer :: A.Parser Offer
parseOffer = Offer <$> price <*> qty
    where price = dropZeroes <$> A.take 5
          qty   = dropZeroes <$> A.take 7
          dropZeroes s = let res = B.dropWhile (== 48) s in if B.null res then "0" else res

toRow :: QuotePacket -> B.ByteString
toRow Packet {..} = B.intercalate (singleton ' ') $ [time, issueCode] ++ bidStrs ++ askStrs
    where bidStrs = map offerStr $ reverse bids
          askStrs = map offerStr asks
          offerStr (Offer p q) = B.concat [q, "@", p]

parsePacket :: A.Parser QuotePacket
parsePacket = do
    A.take 5
    issueCode <- A.take 12
    A.take 12
    bids <- count 5 parseOffer
    A.take 7
    asks <- count 5 parseOffer
    A.take 50
    time <- A.take 8
    A.word8 255
    return Packet {time, bids, asks, issueCode}

getQuotePacket :: PcapHandle -> IO (Maybe TimedQuotePkt)
getQuotePacket handle = do
    (hdr, bs) <- nextBS handle
    if B.null bs
        then return Nothing
        else do
            let quoteBS = snd $ B.breakSubstring "B6034" bs
            case A.parseOnly parsePacket quoteBS of
                Left _  -> getQuotePacket handle
                Right x -> return $ Just (x, hdrTime hdr)

outputUnordered :: PcapHandle -> IO ()
outputUnordered handle = do
    newQuote <- getQuotePacket handle
    case newQuote of
        Just (newQuote, pktTime) -> do
            putStr $ show pktTime ++ " "
            B.putStrLn $ toRow newQuote
            outputUnordered handle
        Nothing -> return ()


main = do
    args <- getArgs
    let path = fromMaybe (error "Provide the path of a dump-file") $ find (/= "-r") args
    handle <- openOffline path
    outputUnordered handle

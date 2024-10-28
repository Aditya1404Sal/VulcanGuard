import Image from "next/image";

export default function Home() {
  return (
    <div className="bg-gray-900 text-gray-100 min-h-screen">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
        {/* Hero Section */}
        <div className="text-center mb-20">
          <h1 className="text-6xl font-bold bg-gradient-to-r from-orange-500 to-red-600 bg-clip-text text-transparent mb-6">
            Vulcan Guard
          </h1>
          <p className="text-xl text-gray-400 max-w-2xl mx-auto">
            Advanced network security and performance management with eBPF-powered protection
          </p>
        </div>

        {/* Features Grid */}
        <div className="grid md:grid-cols-3 gap-8 mb-20">
          {/* Rate Limiter */}
          <div className="bg-gray-800 p-6 rounded-lg hover:bg-gray-750 transition-all">
            <div className="text-orange-500 text-2xl mb-4">⚡</div>
            <h3 className="text-xl font-semibold mb-2">Rate Limiter</h3>
            <p className="text-gray-400">
              Intelligent traffic control with DDoS protection and session brownlisting
            </p>
          </div>

          {/* XDP Packet Filter */}
          <div className="bg-gray-800 p-6 rounded-lg hover:bg-gray-750 transition-all">
            <div className="text-orange-500 text-2xl mb-4">🛡️</div>
            <h3 className="text-xl font-semibold mb-2">eBPF Packet Filter</h3>
            <p className="text-gray-400">
              High-performance packet filtering with minimal latency using XDP
            </p>
          </div>

          {/* Load Balancer */}
          <div className="bg-gray-800 p-6 rounded-lg hover:bg-gray-750 transition-all">
            <div className="text-orange-500 text-2xl mb-4">⚖️</div>
            <h3 className="text-xl font-semibold mb-2">Load Balancer</h3>
            <p className="text-gray-400">
              Multiple algorithms for optimal traffic distribution
            </p>
          </div>
        </div>

        {/* Installation Steps */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mb-20">
          <h2 className="text-3xl font-bold text-center mb-10">Quick Start Guide</h2>
          <div className="grid md:grid-cols-2 gap-8">
            <div className="bg-gray-800 p-6 rounded-lg">
              <h3 className="text-xl font-semibold mb-4">1. Installation</h3>
              <div className="bg-gray-900 p-4 rounded-md">
                <code className="text-sm text-orange-500">
                  git clone https://github.com/yourusername/suboptimal-Firewall.git<br/>
                  cd suboptimal-Firewall<br/>
                  go build
                </code>
              </div>
            </div>

            <div className="bg-gray-800 p-6 rounded-lg">
              <h3 className="text-xl font-semibold mb-4">2. Configuration</h3>
              <div className="bg-gray-900 p-4 rounded-md">
                <code className="text-sm text-orange-500">
                  # Edit configuration file<br/>
                  nano config.yaml<br/>
                  # Set your desired rules and limits
                </code>
              </div>
            </div>

            <div className="bg-gray-800 p-6 rounded-lg">
              <h3 className="text-xl font-semibold mb-4">3. Start Protection</h3>
              <div className="bg-gray-900 p-4 rounded-md">
                <code className="text-sm text-orange-500">
                  sudo Firewall<br/>
                  # Monitor logs<br/>
                  tail -f Firewall.log
                </code>
              </div>
            </div>

            <div className="bg-gray-800 p-6 rounded-lg">
              <h3 className="text-xl font-semibold mb-4">4. Monitor Dashboard</h3>
              <p className="text-gray-400">
                Access the web dashboard at http://localhost:8080 to view real-time metrics and manage your firewall settings.
              </p>
            </div>
          </div>
        </div>

        {/* CTA Section */}
        <div className="text-center">
          <a
            href="https://github.com/Aditya1404Sal/VulcanGuard"
            className="inline-block bg-gradient-to-r from-orange-500 to-red-600 px-8 py-3 rounded-full font-semibold hover:opacity-90 transition-opacity"
            target="_blank"
            rel="noopener noreferrer"
          >
            Get Started →
          </a>
        </div>
      </div>

      {/* Footer */}
      <footer className="border-t border-gray-800 mt-20 py-8">
        <div className="max-w-7xl mx-auto px-4 text-center text-gray-400">
          <p>Vulcan Guard - Advanced Network Security Solution</p>
        </div>
      </footer>
    </div>
  );
}

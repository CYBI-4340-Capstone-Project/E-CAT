function uploadFile() {
    const fileInput = document.getElementById('pcap-upload');
    const file = fileInput.files[0];
    
    if (!file) {
        alert('Please select a PCAP file');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    
    fetch('/Homepage/Network_Classifier/upload', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        displayResults(data);
    })
    .catch(error => {
        console.error('Error:', error);
    });
}

function displayResults(data) {
    const container = document.getElementById('results-container');
    container.style.display = 'block';
    
    // Safely handle undefined values
    const threatType = data.threat_type || 'BENIGN';
    const totalFlows = data.total_flows || 0;
    const maliciousCount = data.malicious_count || 0;
    const accuracy = data.accuracy ? `${(data.accuracy * 100).toFixed(1)}%` : '0%';
    
    // Summary Card
    const summaryCard = document.getElementById('summary-card');
    summaryCard.innerHTML = `
        <div class="card ${threatType !== 'BENIGN' ? 'bg-danger' : 'bg-success'} text-white">
            <div class="card-body">
                <h4>${threatType !== 'BENIGN' ? 'âš ï¸ Malicious Activity Detected' : 'âœ… No Threats Found'}</h4>
                <p>Analyzed ${totalFlows} network flows</p>
                ${threatType !== 'BENIGN' ? `
                    <p>${maliciousCount} malicious flows detected (${accuracy} confidence)</p>
                    <p>Primary threat type: ${threatType}</p>
                    ${data.download_path ? `
                        <p><a href="${data.download_path}" class="btn btn-light btn-sm" download>
                            Download Full Results
                        </a></p>
                    ` : ''}
                ` : ''}
            </div>
        </div>
    `;
    
    // Details Table
    const table = document.getElementById('details-table');
    if (threatType !== 'BENIGN' && data.malicious_flows && data.malicious_flows.length > 0) {
        table.innerHTML = `
            <h4>Malicious Network Flows</h4>
            <div class="table-responsive">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Source</th>
                            <th>Destination</th>
                            <th>Protocol</th>
                            <th>XGB Results</th>
                            <th>DT Results</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.malicious_flows.map(flow => `
                            <tr>
                                <td>${flow.timestamp || ''}</td>
                                <td>${flow.src_ip || ''} : ${flow.src_port || ''}</td>
                                <td>${flow.dst_ip || ''} : ${flow.dst_port || ''}</td>
                                <td>${getProtocolName(flow.protocol)}</td>
                                <td>${flow.final_XGB_prediction || ''} : ${flow.final_XGB_confidence * 100|| ''}</td>
                                <td>${flow.final_DT_prediction || ''} : ${flow.final_DT_confidence * 100|| ''}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    } else {
        table.innerHTML = '';
    }
}

function getProtocolName(protoNum) {
    const protocols = {
        0: 'IP',
        1: 'ICMP',
        2: 'IGMP', 
        3: 'GGP',
        4: 'IPv4',
        6: 'TCP',
        8: 'EGP',
        12: 'PUP',
        17: 'UDP',
        20: 'HMP',
        22: 'XNS-IDP',
        27: 'RDP',
        41: 'IPv6',
        43: 'IPv6-Route',
        44: 'IPv6-Frag',
        60: 'IPv6-Opts',
        66: 'RVD',
        1701: 'L2TP'
    };
    return protocols[protoNum] || protoNum;
}
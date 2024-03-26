document.querySelector('form').addEventListener('submit', async function(event){
    event.preventDefault();

    Swal.fire({
    title: 'Loading...',
    allowOutsideClick: false,
    background: '#404040', 
    didOpen: () => {
        Swal.showLoading();
    }
    });

    const apiKey = '2d4bdbc3b275e3c5d709a00fbdae114851cf26e8a48ea073e71d8c170ac2a27e';
    const url = document.querySelector('input[name="url"]').value;

    const virusTotalUrl = 'https://www.virustotal.com/api/v3/urls';

    const headers = new Headers({
        "Accept": "application/json",
        "x-apikey": apiKey,
        "Content-Type": "application/x-www-form-urlencoded"
      });

    const response = await fetch(virusTotalUrl, {
        method: 'POST',
        headers: headers,
        body:`url=${encodeURIComponent(url)}`,
    });
    Swal.close();

    const data = await response.json();

    if(data.error && data.error.code === "InvalidArgumentError"){
        Swal.fire({ title: "Error!",
        text: "invalid URL, try again",
        icon: "error"
        });
        document.querySelector('input[name="url"]').value = '';
        return;
    }
    else if(data.error){
        console.error('API Error:', data.error);
        Swal.fire({ title: "Error!", 
            text: "Error checking URL. Please try again later.", 
            icon: "error" 
            });
        return;
    }

    const analysisId = data.data.id;
    const reportUrl = `https://www.virustotal.com/api/v3/analyses/${analysisId}`;
    const reportResponse = await fetch(reportUrl, { headers });
    const reportData = await reportResponse.json();
    const maliciousCount = reportData.data.attributes.stats.malicious;
    
    if(maliciousCount > 0){
        Swal.fire({ title: "mallicious!",
        text: "do not use this URL!",
        icon: "warning"
        });
        document.querySelector('input[name="url"]').value = '';
    }
    else {
        Swal.fire({ title: "safe!",
        text: "you can browse safley!",
        icon: "success"
        });
        document.querySelector('input[name="url"]').value = '';
    }
});
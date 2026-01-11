import fetch from 'node-fetch';

const token = "MCrRm7qMxQTHt/q+rz1iS4GOzPZvSkYK6AZBNsTkLQV/sxIXI6gI/mnGNcQm9/gcBMu0A3BQTzGwSGoCsHyfQA==.XhK/TsvALoiHlg3uPz2VFkLPPGOesbmyVpIRZYs8HxY=.guest";
const url = "http://127.0.0.1:8080/graphql";

async function test() {
    console.log("Testing connection to:", url);

    const query = `
    query {
      viewer {
        id
        username
      }
    }
  `;

    // Fallback query if viewer is not available in some versions
    const safeQuery = `
    query {
      findings(first:1) {
        totalCount
      }
    }
  `;

    try {
        const res = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${token}`
            },
            body: JSON.stringify({ query: safeQuery })
        });

        console.log("Status:", res.status);
        const text = await res.text();
        console.log("Response:", text.substring(0, 500)); // Show beginning of response

        if (res.ok) {
            console.log("✅ Connection Successful!");
        } else {
            console.log("❌ Connection Failed");
        }

    } catch (e) {
        console.error("❌ Error:", e.message);
        if (e.code === 'ECONNREFUSED') {
            console.error("Hint: Is Caido running on port 8080?");
        }
    }
}

test();

const ctx = document.getElementById("grafico");

if (ctx) {

    new Chart(ctx, {

        type: "doughnut",

        data: {

            labels: [

                "Baixa",
                "Média",
                "Alta",
                "Crítica"

            ],

            datasets: [{

                data: [15, 25, 12, 9],

                backgroundColor: [

                    "#22C55E",
                    "#EAB308",
                    "#F97316",
                    "#DC2626"

                ],

                borderWidth: 0

            }]

        },

        options: {

            responsive: true,

            plugins: {

                legend: {

                    position: "bottom"

                }

            }

        }

    });

}
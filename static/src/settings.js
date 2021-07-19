function onTabButtonClick(event){
	let tabContentsList = document.querySelectorAll(".tab-content");
	for(let tabContent = 0;tabContent < tabContentsList.length;tabContent++){
		let tab = tabContentsList[tabContent];
		tab.style.display = "none";			
	}
	let tabButtons = document.querySelectorAll(".tab-button");
	for(let tabButton = 0;tabButton < tabButtons.length;tabButton++){
		let button = tabButtons[tabButton];
		button.classList.remove("active");
	}
	this.classList.add("active");
	currentTabContent = this.classList.item(1);
	document.querySelector(".current-tab").innerText = currentTabContent;
	document.querySelector("#"+currentTabContent).style.display = "block";
}

function onDelButtonClick(event){
	let confirmationBox = document.querySelector(".confirmation-box");
	confirmationBox.style.display = "block";
	let crossButton = document.querySelector(".exit");
	crossButton.addEventListener("click",function(event){
		confirmationBox.style.display = "none";
	})
	let confirmationCancelButton = document.querySelector(".conf-cancel-btn");
	confirmationCancelButton.addEventListener("click",function(event){
		confirmationBox.style.display = "none";
	})
}


let tabButtons = document.querySelectorAll(".tab-button");
for(let tabButton = 0;tabButton < tabButtons.length;tabButton++){
	let button =  tabButtons[tabButton];
	button.addEventListener("click",onTabButtonClick);
}

let initialTab = document.querySelector(".current-tab").innerText;
currentButton = document.querySelector("."+initialTab);
currentButton.click();

let deleteButton = document.querySelector(".del-btn");
deleteButton.addEventListener("click",onDelButtonClick);
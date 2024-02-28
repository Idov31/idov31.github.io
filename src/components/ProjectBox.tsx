import Image from "next/image";

interface ProjectBoxProps {
    imagePath: string;
    projectLink: string;
    projectName: string;
    description: string;
}

export default function ProjectBox({imagePath, projectLink, projectName, description}: ProjectBoxProps) {
    return (
        <div className="flex flex-col items-center justify-center bg-bgHomeLine w-full rounded-3xl mt-6
                hover:glow lg:mr-7">
            <a href={projectLink}>
                <div className="flex flex-col items-center justify-center bg-bgHomeLine w-full h-full rounded-3xl
                mx-auto p-5">
                    <Image src={imagePath} alt={projectName} width={203} height={77} />
                    <div className="flex flex-col justify-center items-center">
                        <p className="text-txtHeader font-bold text-3xl pb-4">{projectName}</p>
                        <p className="pb-4 text-xl text-txtSubHeader text-center pr-2 pl-2">{description}</p>
                    </div>
                </div>
            </a>
        </div>
    );
}